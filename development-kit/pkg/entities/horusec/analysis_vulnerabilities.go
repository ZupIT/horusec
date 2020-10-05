package horusec

import (
	"github.com/google/uuid"
	"time"
)

type AnalysisVulnerabilities struct {
	VulnerabilityID uuid.UUID     `gorm:"Column:vulnerability_id"`
	AnalysisID      uuid.UUID     `gorm:"Column:analysis_id"`
	CreatedAt       time.Time     `gorm:"Column:created_at"`
	Vulnerability   Vulnerability `json:"vulnerabilities" gorm:"foreignkey:AnalysisVulnerabilitiesID;association_foreignkey:AnalysisVulnerabilitiesID"` //nolint:lll gorm usage
}

func (a *AnalysisVulnerabilities) GetTable() string {
	return "analysis_vulnerabilities"
}

func (a *AnalysisVulnerabilities) SetCreatedAt() {
	a.CreatedAt = time.Now()
}

func (a *AnalysisVulnerabilities) SetVulnerabilityID(id uuid.UUID) {
	a.VulnerabilityID = id
	a.Vulnerability.VulnerabilityID = id
}

func (a *AnalysisVulnerabilities) SetAnalysisID(id uuid.UUID) {
	a.AnalysisID = id
}
