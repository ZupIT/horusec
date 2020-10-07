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

package management

import (
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api/dto"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	horusecEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/pagination"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
)

type IManagementRepository interface {
	GetAllVulnManagementData(repositoryID uuid.UUID, page, size int, vulnType horusecEnums.VulnerabilityType,
		vulnStatus horusecEnums.VulnerabilityStatus) (vulnManagement dto.VulnManagement, err error)
	Update(vulnerabilityID uuid.UUID, vulnerability *horusec.Vulnerability) (*horusec.Vulnerability, error)
	GetVulnByID(vulnerabilityID uuid.UUID) (*horusec.Vulnerability, error)
}

type Repository struct {
	databaseRead  SQL.InterfaceRead
	databaseWrite SQL.InterfaceWrite
}

func NewManagementRepository(databaseRead SQL.InterfaceRead, databaseWrite SQL.InterfaceWrite) IManagementRepository {
	return &Repository{
		databaseRead:  databaseRead,
		databaseWrite: databaseWrite,
	}
}

func (r *Repository) GetAllVulnManagementData(repositoryID uuid.UUID, page, size int,
	vulnType horusecEnums.VulnerabilityType,
	vulnStatus horusecEnums.VulnerabilityStatus) (vulnManagement dto.VulnManagement, err error) {
	query := r.databaseRead.GetConnection().
		Select("DISTINCT vulnerabilities.vulnerability_id, vulnerabilities.status, vulnerabilities.type," +
			" vulnerabilities.vuln_hash, vulnerabilities.line, vulnerabilities.column, vulnerabilities.confidence," +
			" vulnerabilities.file, vulnerabilities.code, vulnerabilities.details, vulnerabilities.security_tool," +
			" vulnerabilities.language, vulnerabilities.severity").
		Table("analysis").
		Joins("JOIN analysis_vulnerabilities ON analysis.analysis_id = analysis_vulnerabilities.analysis_id").
		Joins("JOIN vulnerabilities ON vulnerabilities.vulnerability_id = analysis_vulnerabilities.vulnerability_id").
		Limit(size).
		Offset(pagination.GetSkip(int64(page), int64(size)))

	vulnManagement.TotalItems = r.getTotalVulnManagementData(repositoryID, vulnType, vulnStatus)
	return vulnManagement, r.setWhereFilter(query, repositoryID, vulnType, vulnStatus).Find(&vulnManagement.Data).Error
}

func (r *Repository) getTotalVulnManagementData(repositoryID uuid.UUID,
	vulnType horusecEnums.VulnerabilityType,
	vulnStatus horusecEnums.VulnerabilityStatus) (count int) {
	query := r.databaseRead.
		GetConnection().
		Select("COUNT( DISTINCT ( vulnerabilities.vulnerability_id ) )").
		Table("analysis").
		Joins("JOIN analysis_vulnerabilities ON analysis.analysis_id = analysis_vulnerabilities.analysis_id").
		Joins("JOIN vulnerabilities ON vulnerabilities.vulnerability_id = analysis_vulnerabilities.vulnerability_id")

	_ = r.setWhereFilter(query, repositoryID, vulnType, vulnStatus).Count(&count)
	return count
}

func (r *Repository) setWhereFilter(query *gorm.DB, repositoryID uuid.UUID,
	vulnType horusecEnums.VulnerabilityType, vulnStatus horusecEnums.VulnerabilityStatus) *gorm.DB {
	if vulnStatus != "" && vulnType != "" {
		return query.Where("repository_id = ? AND vulnerabilities.type = ? AND vulnerabilities.status = ?",
			repositoryID, vulnType, vulnStatus)
	}

	if vulnStatus != "" {
		return query.Where("repository_id = ? AND vulnerabilities.status = ?", repositoryID, vulnStatus)
	}

	if vulnType != "" {
		return query.Where("repository_id = ? AND vulnerabilities.type = ?", repositoryID, vulnType)
	}

	return query.Where("repository_id = ?", repositoryID)
}

func (r *Repository) Update(vulnerabilityID uuid.UUID,
	vulnerability *horusec.Vulnerability) (*horusec.Vulnerability, error) {
	return vulnerability, r.databaseWrite.Update(vulnerability,
		map[string]interface{}{"vulnerability_id": vulnerabilityID}, vulnerability.GetTable()).GetError()
}

func (r *Repository) GetVulnByID(vulnerabilityID uuid.UUID) (*horusec.Vulnerability, error) {
	vulnerability := &horusec.Vulnerability{}
	response := r.databaseRead.Find(vulnerability, r.databaseRead.SetFilter(
		map[string]interface{}{"vulnerability_id": vulnerabilityID}), vulnerability.GetTable())

	return vulnerability, response.GetError()
}
