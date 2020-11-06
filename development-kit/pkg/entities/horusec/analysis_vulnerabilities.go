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

package horusec

import (
	"github.com/google/uuid"
	"time"
)

type AnalysisVulnerabilities struct {
	VulnerabilityID uuid.UUID     `gorm:"Column:vulnerability_id"`
	AnalysisID      uuid.UUID     `gorm:"Column:analysis_id"`
	CreatedAt       time.Time     `gorm:"Column:created_at"`
	Vulnerability   Vulnerability `json:"vulnerabilities" gorm:"foreignkey:VulnerabilityID;association_foreignkey:VulnerabilityID"` //nolint:lll gorm usage
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

func (a *AnalysisVulnerabilities) GetAnalysisVulnerabilitiesWithoutVulnerability() *AnalysisVulnerabilities {
	return &AnalysisVulnerabilities{
		VulnerabilityID: a.VulnerabilityID,
		AnalysisID:      a.AnalysisID,
		CreatedAt:       a.CreatedAt,
	}
}
