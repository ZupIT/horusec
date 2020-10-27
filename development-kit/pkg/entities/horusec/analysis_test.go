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
	"encoding/json"
	"errors"
	horusecEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTableName(t *testing.T) {
	t.Run("should return table name analysis", func(t *testing.T) {
		analysis := &Analysis{}

		assert.Equal(t, "analysis", analysis.GetTable())
	})
}

func TestToBytes(t *testing.T) {
	t.Run("should parse analysis to bytes", func(t *testing.T) {
		analysis := &Analysis{}
		assert.NotEmpty(t, analysis.ToBytes())
	})
}

func TestGetID(t *testing.T) {
	t.Run("should success get analysis id", func(t *testing.T) {
		id := uuid.New()
		analysis := &Analysis{ID: id}
		assert.Equal(t, id, analysis.GetID())
	})
}

func TestGetIDString(t *testing.T) {
	t.Run("should success get analysis id string", func(t *testing.T) {
		id := uuid.New()
		analysis := &Analysis{ID: id}
		assert.Equal(t, id.String(), analysis.GetIDString())
	})
}

func TestToString(t *testing.T) {
	t.Run("should success parse analysis to string", func(t *testing.T) {
		analysis := &Analysis{}
		assert.NotEmpty(t, analysis.ToString())
	})
}

func TestMap(t *testing.T) {
	t.Run("should return a map of analysis", func(t *testing.T) {
		analysis := &Analysis{}
		assert.NotEmpty(t, analysis.Map())
	})
}

func TestSetFindOneFilter(t *testing.T) {
	t.Run("should set find one filter by analysis", func(t *testing.T) {
		analysis := &Analysis{}
		assert.NotEmpty(t, analysis.SetFindOneFilter())
	})
}

func TestSetAnalysisError(t *testing.T) {
	t.Run("should success set error", func(t *testing.T) {
		analysis := &Analysis{}
		analysis.SetAnalysisError(errors.New("test"))
		assert.NotEmpty(t, analysis.Errors)
	})

	t.Run("should success set second and third error", func(t *testing.T) {
		analysis := &Analysis{}
		analysis.SetAnalysisError(errors.New("test"))
		assert.Equal(t, "test", analysis.Errors)
		analysis.SetAnalysisError(errors.New("test"))
		assert.Equal(t, "test, test", analysis.Errors)
		analysis.SetAnalysisError(errors.New("test"))
		assert.Equal(t, "test, test, test", analysis.Errors)
	})
}

func TestSetCompanyName(t *testing.T) {
	t.Run("should success set company name", func(t *testing.T) {
		analysis := &Analysis{}
		analysis.SetCompanyName("test")
		assert.NotEmpty(t, analysis.CompanyName)
	})
}

func TestSetRepositoryName(t *testing.T) {
	t.Run("should success set repository name", func(t *testing.T) {
		analysis := &Analysis{}
		analysis.SetRepositoryName("test")
		assert.NotEmpty(t, analysis.RepositoryName)
	})
}

func TestGenerateID(t *testing.T) {
	t.Run("should success return a new id", func(t *testing.T) {
		analysis := &Analysis{
			AnalysisVulnerabilities: []AnalysisVulnerabilities{
				{},
			},
		}
		analysis.SetupIDInAnalysisContents()

		assert.NotEmpty(t, analysis)
		assert.NotEqual(t, uuid.Nil, analysis.AnalysisVulnerabilities[0].VulnerabilityID)
	})
}

func TestSetAnalysisFinishedData(t *testing.T) {
	t.Run("should set finished data with success", func(t *testing.T) {
		analysis := &Analysis{}
		analysis.SetAnalysisFinishedData()

		assert.NotEmpty(t, analysis.FinishedAt)
		assert.Equal(t, horusecEnum.Success, analysis.Status)
	})

	t.Run("should set finished data with error", func(t *testing.T) {
		analysis := &Analysis{}
		analysis.SetAnalysisError(errors.New("test"))
		analysis.SetAnalysisFinishedData()

		assert.NotEmpty(t, analysis.FinishedAt)
		assert.Equal(t, horusecEnum.Error, analysis.Status)
	})
}

func TestGetTotalVulnerabilities(t *testing.T) {
	t.Run("should return total of 1 vulnerability", func(t *testing.T) {
		analysis := &Analysis{
			AnalysisVulnerabilities: []AnalysisVulnerabilities{{}},
		}

		assert.Equal(t, 1, analysis.GetTotalVulnerabilities())
	})
}

func TestGetTotalVulnerabilitiesBySeverity(t *testing.T) {
	t.Run("should return total vulns by severity", func(t *testing.T) {
		analysis := &Analysis{
			AnalysisVulnerabilities: []AnalysisVulnerabilities{
				{
					Vulnerability: Vulnerability{Type: horusecEnum.Vulnerability, Severity: severity.Low},
				},
				{
					Vulnerability: Vulnerability{Type: horusecEnum.Vulnerability, Severity: severity.Low},
				},
				{
					Vulnerability: Vulnerability{Type: horusecEnum.Vulnerability, Severity: severity.Audit},
				},
				{
					Vulnerability: Vulnerability{Type: horusecEnum.Vulnerability, Severity: severity.Medium},
				},
				{
					Vulnerability: Vulnerability{Type: horusecEnum.Vulnerability, Severity: severity.High},
				},
				{
					Vulnerability: Vulnerability{Type: horusecEnum.Vulnerability, Severity: severity.High},
				},
				{
					Vulnerability: Vulnerability{Type: horusecEnum.Vulnerability, Severity: severity.Info},
				},
			},
		}

		assert.Equal(t, 2, analysis.GetTotalVulnerabilitiesBySeverity()[horusecEnum.Vulnerability][severity.Low])
		assert.Equal(t, 1, analysis.GetTotalVulnerabilitiesBySeverity()[horusecEnum.Vulnerability][severity.Medium])
		assert.Equal(t, 2, analysis.GetTotalVulnerabilitiesBySeverity()[horusecEnum.Vulnerability][severity.High])
		assert.Equal(t, 1, analysis.GetTotalVulnerabilitiesBySeverity()[horusecEnum.Vulnerability][severity.Audit])
		assert.Equal(t, 0, analysis.GetTotalVulnerabilitiesBySeverity()[horusecEnum.Vulnerability][severity.NoSec])
		assert.Equal(t, 1, analysis.GetTotalVulnerabilitiesBySeverity()[horusecEnum.Vulnerability][severity.Info])
	})
}

func TestSortVulnerabilitiesByCriticality(t *testing.T) {
	t.Run("should return total of 1 vulnerability", func(t *testing.T) {
		analysis := &Analysis{
			AnalysisVulnerabilities: []AnalysisVulnerabilities{
				{
					Vulnerability: Vulnerability{Severity: severity.Low},
				},
				{
					Vulnerability: Vulnerability{Severity: severity.Medium},
				},
				{
					Vulnerability: Vulnerability{Severity: severity.High},
				},
			},
		}

		analysis.SortVulnerabilitiesByCriticality()

		assert.Equal(t, severity.High, analysis.AnalysisVulnerabilities[0].Vulnerability.Severity)
		assert.Equal(t, severity.Medium, analysis.AnalysisVulnerabilities[1].Vulnerability.Severity)
		assert.Equal(t, severity.Low, analysis.AnalysisVulnerabilities[2].Vulnerability.Severity)
	})
}

func TestSetRepositoryID(t *testing.T) {
	t.Run("should success set repository id", func(t *testing.T) {
		analysis := &Analysis{}
		analysis.SetRepositoryID(uuid.New())
		assert.NotEmpty(t, analysis.RepositoryID)
	})
}

func TestSortVulnerabilitiesByType(t *testing.T) {
	t.Run("should success set repository id", func(t *testing.T) {
		analysis := &Analysis{
			AnalysisVulnerabilities: []AnalysisVulnerabilities{
				{
					Vulnerability: Vulnerability{
						Type: horusecEnum.Corrected,
					},
				},
				{
					Vulnerability: Vulnerability{
						Type: horusecEnum.Vulnerability,
					},
				},
				{
					Vulnerability: Vulnerability{
						Type: horusecEnum.FalsePositive,
					},
				},
				{
					Vulnerability: Vulnerability{
						Type: horusecEnum.RiskAccepted,
					},
				},
			},
		}

		result := analysis.SortVulnerabilitiesByType()
		assert.Equal(t, result.AnalysisVulnerabilities[0].Vulnerability.Type, horusecEnum.Vulnerability)
		assert.Equal(t, result.AnalysisVulnerabilities[1].Vulnerability.Type, horusecEnum.RiskAccepted)
		assert.Equal(t, result.AnalysisVulnerabilities[2].Vulnerability.Type, horusecEnum.FalsePositive)
		assert.Equal(t, result.AnalysisVulnerabilities[3].Vulnerability.Type, horusecEnum.Corrected)
	})
}

func TestGetAnalysisWithoutAnalysisVulnerabilities(t *testing.T) {
	t.Run("should success get analysis without vulnerabilities", func(t *testing.T) {
		analysis := &Analysis{
			ID: uuid.New(),
		}
		assert.Empty(t, analysis.GetAnalysisWithoutAnalysisVulnerabilities().AnalysisVulnerabilities)
	})
}

func TestSetDefaultVulnerabilityType(t *testing.T) {
	t.Run("should success set vuln type default", func(t *testing.T) {
		analysis := &Analysis{
			AnalysisVulnerabilities: []AnalysisVulnerabilities{
				{
					Vulnerability: Vulnerability{},
				},
			},
		}

		analysis.SetDefaultVulnerabilityType()
		assert.Equal(t, analysis.AnalysisVulnerabilities[0].Vulnerability.Type, horusecEnum.Vulnerability)
	})
}

func TestSetFalsePositivesAndRiskAcceptInVulnerabilities(t *testing.T) {
	t.Run("should success set false positive and risk accepted types", func(t *testing.T) {
		analysis := &Analysis{
			AnalysisVulnerabilities: []AnalysisVulnerabilities{
				{
					Vulnerability: Vulnerability{
						VulnHash: "1",
					},
				},
				{
					Vulnerability: Vulnerability{
						VulnHash: "2",
					},
				},
			},
		}

		analysis.SetFalsePositivesAndRiskAcceptInVulnerabilities([]string{"1"}, []string{"2"})
		assert.Equal(t, analysis.AnalysisVulnerabilities[0].Vulnerability.Type, horusecEnum.FalsePositive)
		assert.Equal(t, analysis.AnalysisVulnerabilities[1].Vulnerability.Type, horusecEnum.RiskAccepted)
	})
}

func TestParseResponseBytesToAnalysis(t *testing.T) {
	t.Run("Should ParseResponseBytesToAnalysis without errors", func(t *testing.T) {
		analysis := &Analysis{
			AnalysisVulnerabilities: []AnalysisVulnerabilities{
				{
					Vulnerability: Vulnerability{
						VulnHash: "1",
					},
				},
			},
		}
		body := map[string]interface{}{
			"content": analysis,
		}
		bodyBytes, err := json.Marshal(body)
		assert.NoError(t, err)
		newAnalysis, err := analysis.ParseResponseBytesToAnalysis(bodyBytes)
		assert.NoError(t, err)
		assert.NotEmpty(t, newAnalysis)
	})
	t.Run("Should ParseResponseBytesToAnalysis with errors in unmarshal content", func(t *testing.T) {
		analysis := &Analysis{}
		newAnalysis, err := analysis.ParseResponseBytesToAnalysis(nil)
		assert.Error(t, err)
		assert.Empty(t, newAnalysis)
	})
}