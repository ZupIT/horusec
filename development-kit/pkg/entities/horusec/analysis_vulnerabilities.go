package horusec

import (
	"github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/google/uuid"
)

type AnalysisVulnerabilities struct {
	AnalysisVulnerabilitiesID uuid.UUID                           `gorm:"Column:analysis_vulnerabilities_id"`
	VulnerabilityID           uuid.UUID                           `gorm:"Column:vulnerability_id"`
	AnalysisID                uuid.UUID                           `gorm:"Column:analysis_id"`
	Type                      horusec.AnalysisVulnerabilitiesType `gorm:"Column:type"`
	IsApproved                bool                                `gorm:"Column:is_approved"`
	Vulnerability             Vulnerability                       `json:"vulnerabilities" gorm:"foreignkey:AnalysisVulnerabilitiesID;association_foreignkey:AnalysisVulnerabilitiesID"` //nolint:lll gorm usage
}

func (a *AnalysisVulnerabilities) GetTable() string {
	return "analysis_vulnerabilities"
}
