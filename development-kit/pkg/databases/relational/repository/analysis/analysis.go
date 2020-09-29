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
	response := conn.Create(analysis, analysis.GetTable())
	return response.GetError()
}

func (ar *Repository) GetByID(analysisID uuid.UUID) (*horusec.Analysis, error) {
	analysis := &horusec.Analysis{}
	query := ar.databaseRead.
		SetFilter(map[string]interface{}{"analysis_id": analysisID.String()}).
		Limit(1).
		Preload("Vulnerabilities")
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
		Select("analysis.repository_id, analysis.repository_name, analysis.company_id, analysis.company_name," +
			" analysis.status, analysis.errors, analysis.created_at, analysis.finished_at," +
			" vulnerabilities.line, vulnerabilities.column, vulnerabilities.confidence, vulnerabilities.file," +
			" vulnerabilities.code, vulnerabilities.details, vulnerabilities.type, vulnerabilities.vulnerable_below," +
			" vulnerabilities.version, vulnerabilities.security_tool, vulnerabilities.language," +
			" vulnerabilities.severity, vulnerabilities.commit_author, vulnerabilities.commit_email," +
			" vulnerabilities.commit_hash, vulnerabilities.commit_message, vulnerabilities.commit_date," +
			" vulnerabilities.vuln_hash").
		Table("analysis").
		Joins("JOIN vulnerabilities ON analysis.analysis_id = vulnerabilities.analysis_id").
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
		Joins("JOIN vulnerabilities ON analysis.analysis_id = vulnerabilities.analysis_id")

	query = ar.setWhereFilter(query, companyID, repositoryID, initialDate, finalDate).Count(&count)

	return count, query.Error
}

func (ar *Repository) GetDeveloperCount(companyID, repositoryID uuid.UUID, initialDate,
	finalDate time.Time) (count int, err error) {
	query := ar.databaseRead.
		GetConnection().
		Table("analysis").
		Select("COUNT( DISTINCT ( vulnerabilities.commit_email ) )").
		Joins("JOIN vulnerabilities ON analysis.analysis_id = vulnerabilities.analysis_id")

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
		Select("vulnerabilities.severity AS severity, COUNT(vulnerabilities.vulnerability_id) AS total").
		Table("analysis").
		Joins("JOIN vulnerabilities ON analysis.analysis_id = vulnerabilities.analysis_id").
		Group("vulnerabilities.severity")

	query = ar.setWhereFilter(query, companyID, repositoryID, initialDate, finalDate).Find(&vulnBySeverity)

	return vulnBySeverity, query.Error
}

func (ar *Repository) GetVulnByDeveloper(companyID, repositoryID uuid.UUID, initialDate,
	finalDate time.Time) (vulnByDeveloper []dashboard.VulnByDeveloper, err error) {
	query := ar.databaseRead.
		GetConnection().
		Select("vulnerabilities.commit_email AS developer, COUNT(vulnerabilities.vulnerability_id) AS total,"+
			" (?) AS low, (?) AS medium, (?) AS high, (?) AS audit, (?) AS no_sec, (?) AS info",
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "commit_email", "LOW"),
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "commit_email", "MEDIUM"),
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "commit_email", "HIGH"),
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "commit_email", "AUDIT"),
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "commit_email", "NOSEC"),
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "commit_email", "INFO")).
		Table("analysis").
		Joins("JOIN vulnerabilities ON analysis.analysis_id = vulnerabilities.analysis_id").
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
		Select("vulnerabilities.language AS language, COUNT(vulnerabilities.vulnerability_id) AS total,"+
			" (?) AS low, (?) AS medium, (?) AS high, (?) AS audit, (?) AS no_sec, (?) AS info",
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "language", "LOW"),
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "language", "MEDIUM"),
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "language", "HIGH"),
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "language", "AUDIT"),
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "language", "NOSEC"),
			ar.getSubQueryByVulnerability(companyID, repositoryID, initialDate, finalDate, "language", "INFO")).
		Table("analysis").
		Joins("JOIN vulnerabilities ON analysis.analysis_id = vulnerabilities.analysis_id").
		Group("vulnerabilities.language")

	query = ar.setWhereFilter(query, companyID, repositoryID, initialDate, finalDate).Find(&vulnByLanguage)

	return vulnByLanguage, query.Error
}

func (ar *Repository) GetVulnByRepository(companyID, repositoryID uuid.UUID, initialDate,
	finalDate time.Time) (vulnByRepository []dashboard.VulnByRepository, err error) {
	query := ar.databaseRead.
		GetConnection().
		Select(" MAX(analysis.repository_name) AS repository, COUNT(vulnerabilities.vulnerability_id) AS total,"+
			" (?) AS low, (?) AS medium, (?) AS high, (?) AS audit, (?) AS no_sec, (?) AS info",
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "repository_id", "LOW"),
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "repository_id", "MEDIUM"),
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "repository_id", "HIGH"),
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "repository_id", "AUDIT"),
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "repository_id", "NOSEC"),
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "repository_id", "INFO")).
		Table("analysis").
		Joins("JOIN vulnerabilities ON analysis.analysis_id = vulnerabilities.analysis_id").
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
		Select("analysis.finished_at AS time, COUNT(vulnerabilities.vulnerability_id) AS total,"+
			" (?) AS low, (?) AS medium, (?) AS high, (?) AS audit, (?) AS no_sec, (?) AS info",
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "finished_at", "LOW"),
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "finished_at", "MEDIUM"),
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "finished_at", "HIGH"),
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "finished_at", "AUDIT"),
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "finished_at", "NOSEC"),
			ar.getSubQueryByAnalysis(companyID, repositoryID, initialDate, finalDate, "finished_at", "INFO")).
		Table("analysis").
		Joins("JOIN vulnerabilities ON analysis.analysis_id = vulnerabilities.analysis_id").
		Group("analysis.finished_at")

	query = ar.setWhereFilter(query, companyID, repositoryID, initialDate, finalDate).Find(&vulnByTime)

	return vulnByTime, query.Error
}

func (ar *Repository) getSubQueryByAnalysis(companyID, repositoryID uuid.UUID, initialDate,
	finalDate time.Time, field, severity string) *gorm.SqlExpr {
	subQuery := ar.databaseRead.
		GetConnection().
		Select("COUNT(vuln.vulnerability_id)").
		Table("analysis AS ana").
		Joins("JOIN vulnerabilities AS vuln ON ana.analysis_id = vuln.analysis_id").
		Where(fmt.Sprintf("ana.%s = analysis.%s AND vuln.severity = ?", field, field), severity)

	return ar.setWhereFilter(subQuery, companyID, repositoryID, initialDate, finalDate).SubQuery()
}

func (ar *Repository) getSubQueryByVulnerability(companyID, repositoryID uuid.UUID, initialDate,
	finalDate time.Time, field, severity string) *gorm.SqlExpr {
	subQuery := ar.databaseRead.
		GetConnection().
		Select("COUNT(vuln.vulnerability_id)").
		Table("analysis AS ana").
		Joins("JOIN vulnerabilities AS vuln ON ana.analysis_id = vuln.analysis_id").
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
