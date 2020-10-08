// Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//nolint
package analysis

import "C"
import (
	"fmt"
	"strings"
	"time"

	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/dashboard"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/pagination"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
)

type IAnalysisRepository interface {
	Create(analysis *horusec.Analysis, tx SQL.InterfaceWrite) error
	GetByID(analysisID uuid.UUID) (*horusec.Analysis, error)
	GetDetailsPaginated(companyID, repositoryID uuid.UUID, page, size int, initialDate,
		finalDate time.Time) (vulnDetails []dashboard.VulnDetails, err error)
	GetDetailsCount(companyID, repositoryID uuid.UUID, initialDate,
		finalDate time.Time) (count int, err error)
	GetDeveloperCount(companyID, repositoryID uuid.UUID, initialDate,
		finalDate time.Time) (count int, err error)
	GetRepositoryCount(companyID, repositoryID uuid.UUID, initialDate,
		finalDate time.Time) (count int, err error)
	GetVulnBySeverity(companyID, repositoryID uuid.UUID, initialDate,
		finalDate time.Time) (vulnBySeverity []dashboard.VulnBySeverity, err error)
	GetVulnByDeveloper(companyID, repositoryID uuid.UUID, initialDate,
		finalDate time.Time) (vulnByDeveloper []dashboard.VulnByDeveloper, err error)
	GetVulnByLanguage(companyID, repositoryID uuid.UUID, initialDate,
		finalDate time.Time) (vulnByLanguage []dashboard.VulnByLanguage, err error)
	GetVulnByRepository(companyID, repositoryID uuid.UUID, initialDate,
		finalDate time.Time) (vulnByRepository []dashboard.VulnByRepository, err error)
	GetVulnByTime(companyID, repositoryID uuid.UUID, initialDate,
		finalDate time.Time) (vulnByTime []dashboard.VulnByTime, err error)
}

type Repository struct {
	databaseRead  SQL.InterfaceRead
	databaseWrite SQL.InterfaceWrite
}

func NewAnalysisRepository(databaseRead SQL.InterfaceRead, databaseWrite SQL.InterfaceWrite) IAnalysisRepository {
	return &Repository{
		databaseRead:  databaseRead,
		databaseWrite: databaseWrite,
	}
}

func (ar *Repository) Create(analysis *horusec.Analysis, tx SQL.InterfaceWrite) error {
	conn := ar.databaseWrite
	if tx != nil {
		conn = tx
	}
	// First create analysis without Many to Many and without Vulnerability
	if err := ar.createAnalysis(conn, analysis); err != nil {
		return err
	}

	// Validate if already exists vulnerability to create other fields
	if err := ar.validateToCreateManyToMany(conn, analysis); err != nil {
		return err
	}
	return nil
}

func (ar *Repository) createAnalysis(conn SQL.InterfaceWrite, analysis *horusec.Analysis) error {
	return conn.Create(analysis.GetAnalysisWithoutAnalysisVulnerabilities(), analysis.GetTable()).GetError()
}

func (ar *Repository) validateToCreateManyToMany(conn SQL.InterfaceWrite, analysis *horusec.Analysis) error {
	for key := range analysis.AnalysisVulnerabilities {
		vuln := analysis.AnalysisVulnerabilities[key].Vulnerability
		// Validate if already exists vulnerability lookup hash and repositoryID
		vulnerabilityID, err := ar.getVulnerabilityIDByHashAndRepositoryID(vuln.VulnHash, analysis.RepositoryID, conn.GetConnection())
		if err != nil {
			return err
		}
		// Now create ManyToMany and vulnerability if not exists
		if err = ar.createManyToManyAndVulnerability(vulnerabilityID, &analysis.AnalysisVulnerabilities[key], conn); err != nil {
			return err
		}
	}
	return nil
}

func (ar *Repository) createManyToManyAndVulnerability(vulnerabilityID uuid.UUID,
	currentAnalyseVulnerability *horusec.AnalysisVulnerabilities, conn SQL.InterfaceWrite) error {
	// Now get ManyToMany without Vulnerability
	analyseVulnerability := currentAnalyseVulnerability.GetAnalysisVulnerabilitiesWithoutVulnerability()
	// Get new vulnerability to create
	vuln := currentAnalyseVulnerability.Vulnerability
	if vulnerabilityID != uuid.Nil {
		// If exists vulnerability we need replace generic VulnerabilityID to existing vulnerability in DB
		analyseVulnerability.VulnerabilityID = vulnerabilityID
		// If not exists we need create vulnerability with instance InterfaceWrite
	} else if err := ar.execCreateVulnerability(vuln, conn); err != nil {
		return err
	}
	// Now we create Analysis and Vulnerability is possible create ManyToMany
	return ar.execCreateAnalysisVulnerabilities(*analyseVulnerability, conn.GetConnection())
}

func (ar *Repository) getVulnerabilityIDByHashAndRepositoryID(vulnHash string, repositoryID uuid.UUID, conn *gorm.DB) (vulnerabilityID uuid.UUID, err error) {
	vulnerability := horusec.Vulnerability{}
	// To validate if already exists this vulnerability inside of repository we need find by hash and repositoryID
	query := conn.
		Joins("INNER JOIN analysis_vulnerabilities ON vulnerabilities.vulnerability_id = analysis_vulnerabilities.vulnerability_id").
		Joins("INNER JOIN analysis ON analysis_vulnerabilities.analysis_id = analysis.analysis_id").
		Where("analysis.repository_id = ?", repositoryID.String()).
		Where(map[string]interface{}{"vuln_hash": vulnHash}).
		Table(vulnerability.GetTable()).Find(&vulnerability)
	if query.Error != nil {
		// If error is "record not found" is not necessary procced because we go add new vulnerability
		if strings.EqualFold(query.Error.Error(), "record not found") {
			return uuid.Nil, nil
		}
		// If error unknown is need validate
		return uuid.Nil, query.Error
	}
	// Else we return VulnerabilityID of existing vulnerability
	return vulnerability.VulnerabilityID, nil
}

func (ar *Repository) execCreateVulnerability(vul horusec.Vulnerability, conn SQL.InterfaceWrite) error {
	return conn.Create(vul, vul.GetTable()).GetError()
}

func (ar *Repository) execCreateAnalysisVulnerabilities(analysisVulnerabilities horusec.AnalysisVulnerabilities,
	conn *gorm.DB) error {
	entityToCheck := horusec.AnalysisVulnerabilities{}
	// Before create ManyToMany we need lookup inside transaction if was generated this many to many in other loop
	query := conn.
		Where("analysis_id = ? AND vulnerability_id = ?", analysisVulnerabilities.AnalysisID, analysisVulnerabilities.VulnerabilityID).
		Table(analysisVulnerabilities.GetTable()).
		Find(&entityToCheck)
	// If return error we need validate
	if query.Error != nil && !strings.EqualFold(query.Error.Error(), "record not found") {
		return query.Error
	}
	// If already exists this VulnerabilityID and AnalysisID in database is not necessary add again.
	if entityToCheck.VulnerabilityID != uuid.Nil && entityToCheck.AnalysisID != uuid.Nil {
		return nil
	}
	// If error is "record not found" or not exists VulnerabilityID/AnalysisID we need create ManyToMany
	return conn.Table(analysisVulnerabilities.GetTable()).Create(analysisVulnerabilities).Error
}

func (ar *Repository) GetByID(analysisID uuid.UUID) (*horusec.Analysis, error) {
	analysis := &horusec.Analysis{}
	query := ar.databaseRead.
		SetFilter(map[string]interface{}{"analysis_id": analysisID.String()}).
		Limit(1).
		Preload("AnalysisVulnerabilities").
		Preload("AnalysisVulnerabilities.Vulnerability")
	response := ar.databaseRead.Find(analysis, query, analysis.GetTable())
	if err := response.GetError(); err != nil {
		return nil, err
	}
	return response.GetData().(*horusec.Analysis), nil
}

func (ar *Repository) GetDetailsPaginated(companyID, repositoryID uuid.UUID, page, size int, initialDate,
	finalDate time.Time) (vulnDetails []dashboard.VulnDetails, err error) {
	query := ar.databaseRead.
		GetConnection().
		Select("DISTINCT ON (vulnerabilities.vulnerability_id) vulnerabilities.vulnerability_id," +
			" analysis.repository_id, analysis.repository_name, analysis.company_id, analysis.company_name," +
			" analysis.status, analysis.errors, analysis.created_at, analysis.finished_at, vulnerabilities.line," +
			" vulnerabilities.column, vulnerabilities.confidence, vulnerabilities.file,vulnerabilities.code," +
			" vulnerabilities.details, vulnerabilities.security_tool, vulnerabilities.language," +
			" vulnerabilities.severity, vulnerabilities.commit_author, vulnerabilities.commit_email," +
			" vulnerabilities.commit_hash, vulnerabilities.commit_message, vulnerabilities.commit_date," +
			" vulnerabilities.vuln_hash").
		Table("analysis").
		Joins("JOIN analysis_vulnerabilities ON analysis.analysis_id = analysis_vulnerabilities.analysis_id").
		Joins("JOIN vulnerabilities ON vulnerabilities.vulnerability_id = analysis_vulnerabilities.vulnerability_id").
		Limit(size).
		Offset(pagination.GetSkip(int64(page), int64(size)))

	query = ar.setWhereFilter(query, companyID, repositoryID, initialDate, finalDate).Find(&vulnDetails)

	return vulnDetails, query.Error
}

func (ar *Repository) GetDetailsCount(companyID, repositoryID uuid.UUID, initialDate,
	finalDate time.Time) (count int, err error) {
	query := ar.databaseRead.
		GetConnection().
		Table("analysis").
		Select("COUNT( DISTINCT ( vulnerabilities ) )").
		Joins("JOIN analysis_vulnerabilities ON analysis.analysis_id = analysis_vulnerabilities.analysis_id").
		Joins("JOIN vulnerabilities ON vulnerabilities.vulnerability_id = analysis_vulnerabilities.vulnerability_id")

	query = ar.setWhereFilter(query, companyID, repositoryID, initialDate, finalDate).Count(&count)

	return count, query.Error
}

func (ar *Repository) GetDeveloperCount(companyID, repositoryID uuid.UUID, initialDate,
	finalDate time.Time) (count int, err error) {
	query := ar.databaseRead.
		GetConnection().
		Table("analysis").
		Select("COUNT( DISTINCT ( vulnerabilities.commit_email ) )").
		Joins("JOIN analysis_vulnerabilities ON analysis.analysis_id = analysis_vulnerabilities.analysis_id").
		Joins("JOIN vulnerabilities ON vulnerabilities.vulnerability_id = analysis_vulnerabilities.vulnerability_id")

	query = ar.setWhereFilter(query, companyID, repositoryID, initialDate, finalDate).Count(&count)

	return count, query.Error
}

func (ar *Repository) GetRepositoryCount(companyID, repositoryID uuid.UUID, initialDate,
	finalDate time.Time) (count int, err error) {
	query := ar.databaseRead.
		GetConnection().
		Table("analysis").
		Select("COUNT( DISTINCT ( analysis.repository_id ) )")

	query = ar.setWhereFilter(query, companyID, repositoryID, initialDate, finalDate).Count(&count)

	return count, query.Error
}

func (ar *Repository) GetVulnBySeverity(companyID, repositoryID uuid.UUID, initialDate,
	finalDate time.Time) (vulnBySeverity []dashboard.VulnBySeverity, err error) {
	query := ar.databaseRead.
		GetConnection().
		Select("vulnerabilities.severity AS severity, COUNT( DISTINCT (vulnerabilities.vulnerability_id) ) AS total").
		Table("analysis").
		Joins("JOIN analysis_vulnerabilities ON analysis.analysis_id = analysis_vulnerabilities.analysis_id").
		Joins("JOIN vulnerabilities ON vulnerabilities.vulnerability_id = analysis_vulnerabilities.vulnerability_id").
		Group("vulnerabilities.severity")

	query = ar.setWhereFilter(query, companyID, repositoryID, initialDate, finalDate).Find(&vulnBySeverity)

	return vulnBySeverity, query.Error
}

func (ar *Repository) GetVulnByDeveloper(companyID, repositoryID uuid.UUID, initialDate,
	finalDate time.Time) (vulnByDeveloper []dashboard.VulnByDeveloper, err error) {
	query := ar.databaseRead.
		GetConnection().
		Select("vulnerabilities.commit_email AS developer, COUNT( DISTINCT (vulnerabilities.vulnerability_id) ) AS total,"+
			" (?) AS low, (?) AS medium, (?) AS high, (?) AS audit, (?) AS no_sec, (?) AS info",
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "commit_email", "LOW"),
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "commit_email", "MEDIUM"),
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "commit_email", "HIGH"),
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "commit_email", "AUDIT"),
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "commit_email", "NOSEC"),
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "commit_email", "INFO")).
		Table("analysis").
		Joins("JOIN analysis_vulnerabilities ON analysis.analysis_id = analysis_vulnerabilities.analysis_id").
		Joins("JOIN vulnerabilities ON vulnerabilities.vulnerability_id = analysis_vulnerabilities.vulnerability_id").
		Group("vulnerabilities.commit_email").
		Order("total DESC", true).
		Limit(5)

	query = ar.setWhereFilter(query, companyID, repositoryID, initialDate, finalDate).Find(&vulnByDeveloper)

	return vulnByDeveloper, query.Error
}

func (ar *Repository) GetVulnByLanguage(companyID, repositoryID uuid.UUID, initialDate,
	finalDate time.Time) (vulnByLanguage []dashboard.VulnByLanguage, err error) {
	query := ar.databaseRead.
		GetConnection().
		Select("vulnerabilities.language AS language, COUNT( DISTINCT (vulnerabilities.vulnerability_id) ) AS total,"+
			" (?) AS low, (?) AS medium, (?) AS high, (?) AS audit, (?) AS no_sec, (?) AS info",
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "language", "LOW"),
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "language", "MEDIUM"),
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "language", "HIGH"),
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "language", "AUDIT"),
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "language", "NOSEC"),
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "language", "INFO")).
		Table("analysis").
		Joins("JOIN analysis_vulnerabilities ON analysis.analysis_id = analysis_vulnerabilities.analysis_id").
		Joins("JOIN vulnerabilities ON vulnerabilities.vulnerability_id = analysis_vulnerabilities.vulnerability_id").
		Group("vulnerabilities.language")

	query = ar.setWhereFilter(query, companyID, repositoryID, initialDate, finalDate).Find(&vulnByLanguage)

	return vulnByLanguage, query.Error
}

func (ar *Repository) GetVulnByRepository(companyID, repositoryID uuid.UUID, initialDate,
	finalDate time.Time) (vulnByRepository []dashboard.VulnByRepository, err error) {
	query := ar.databaseRead.
		GetConnection().
		Select(" MAX(analysis.repository_name) AS repository, COUNT( DISTINCT (vulnerabilities.vulnerability_id) ) AS total,"+
			" (?) AS low, (?) AS medium, (?) AS high, (?) AS audit, (?) AS no_sec, (?) AS info",
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "repository_id", "LOW"),
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "repository_id", "MEDIUM"),
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "repository_id", "HIGH"),
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "repository_id", "AUDIT"),
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "repository_id", "NOSEC"),
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "repository_id", "INFO")).
		Table("analysis").
		Joins("JOIN analysis_vulnerabilities ON analysis.analysis_id = analysis_vulnerabilities.analysis_id").
		Joins("JOIN vulnerabilities ON vulnerabilities.vulnerability_id = analysis_vulnerabilities.vulnerability_id").
		Group("analysis.repository_id").
		Order("total DESC", true).
		Limit(5)

	query = ar.setWhereFilter(query, companyID, repositoryID, initialDate, finalDate).Find(&vulnByRepository)

	return vulnByRepository, query.Error
}

func (ar *Repository) GetVulnByTime(companyID, repositoryID uuid.UUID, initialDate,
	finalDate time.Time) (vulnByTime []dashboard.VulnByTime, err error) {
	query := ar.databaseRead.
		GetConnection().
		Select("analysis.finished_at AS time, COUNT( DISTINCT (vulnerabilities.vulnerability_id) ) AS total,"+
			" (?) AS low, (?) AS medium, (?) AS high, (?) AS audit, (?) AS no_sec, (?) AS info",
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "finished_at", "LOW"),
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "finished_at", "MEDIUM"),
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "finished_at", "HIGH"),
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "finished_at", "AUDIT"),
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "finished_at", "NOSEC"),
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "finished_at", "INFO")).
		Table("analysis").
		Joins("JOIN analysis_vulnerabilities ON analysis.analysis_id = analysis_vulnerabilities.analysis_id").
		Joins("JOIN vulnerabilities ON vulnerabilities.vulnerability_id = analysis_vulnerabilities.vulnerability_id").
		Group("analysis.finished_at")

	query = ar.setWhereFilter(query, companyID, repositoryID, initialDate, finalDate).Find(&vulnByTime)

	return vulnByTime, query.Error
}

func (ar *Repository) getSubQueryByAnalysis(companyID, repositoryID uuid.UUID, initialDate,
	finalDate time.Time, field, severity string) *gorm.SqlExpr {
	subQuery := ar.databaseRead.
		GetConnection().
		Select("COUNT( DISTINCT (vuln.vulnerability_id) )").
		Table("analysis AS ana").
		Joins("JOIN analysis_vulnerabilities ON ana.analysis_id = analysis_vulnerabilities.analysis_id").
		Joins("JOIN vulnerabilities AS vuln ON vuln.vulnerability_id = analysis_vulnerabilities.vulnerability_id").
		Where(fmt.Sprintf("ana.%s = analysis.%s AND vuln.severity = ?", field, field), severity)

	return ar.setWhereFilter(subQuery, companyID, repositoryID, initialDate, finalDate).SubQuery()
}

func (ar *Repository) getSubQueryByVulnerability(companyID, repositoryID uuid.UUID, initialDate,
	finalDate time.Time, field, severity string) *gorm.SqlExpr {
	subQuery := ar.databaseRead.
		GetConnection().
		Select("COUNT( DISTINCT (vuln.vulnerability_id) )").
		Table("analysis AS ana").
		Joins("JOIN analysis_vulnerabilities ON ana.analysis_id = analysis_vulnerabilities.analysis_id").
		Joins("JOIN vulnerabilities AS vuln ON vuln.vulnerability_id = analysis_vulnerabilities.vulnerability_id").
		Where(fmt.Sprintf("vuln.%s = vulnerabilities.%s AND vuln.severity = ?", field, field), severity)

	return ar.setWhereFilter(subQuery, companyID, repositoryID, initialDate, finalDate).SubQuery()
}

func (ar *Repository) setWhereFilter(query *gorm.DB, companyID, repositoryID uuid.UUID, initialDate,
	finalDate time.Time) *gorm.DB {
	if companyID != uuid.Nil {
		return query.Where("finished_at BETWEEN ? AND ? AND company_id = ?",
			initialDate, finalDate, companyID)
	}

	return query.Where("finished_at BETWEEN ? AND ? AND repository_id = ?",
		initialDate, finalDate, repositoryID)
}
