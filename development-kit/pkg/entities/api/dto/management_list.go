package dto

import (
	horusecEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/google/uuid"
)

type ManagementList struct {
	AnalysisID      uuid.UUID                                  `json:"analysisID"`
	VulnerabilityID uuid.UUID                                  `json:"vulnerabilityID"`
	RepositoryID    uuid.UUID                                  `json:"repositoryID"`
	CompanyID       uuid.UUID                                  `json:"companyID"`
	Status          horusecEnums.AnalysisVulnerabilitiesStatus `json:"status"`
	Type            horusecEnums.AnalysisVulnerabilitiesType   `json:"type"`
	VulnHash        string                                     `json:"vulnHash"`
	Line            string                                     `json:"line"`
	Column          string                                     `json:"column"`
	Confidence      string                                     `json:"confidence"`
	File            string                                     `json:"file"`
	Code            string                                     `json:"code"`
	Details         string                                     `json:"details"`
	SecurityTool    tools.Tool                                 `json:"securityTool"`
	Language        languages.Language                         `json:"language"`
	Severity        severity.Severity                          `json:"severity"`
}
