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
	"errors"
	"testing"

	horusecEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
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
		analysis := &Analysis{}
		analysis.GenerateID()

		assert.NotEmpty(t, analysis)
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
			Vulnerabilities: []Vulnerability{{}},
		}

		assert.Equal(t, 1, analysis.GetTotalVulnerabilities())
	})
}

func TestGetTotalVulnerabilitiesBySeverity(t *testing.T) {
	t.Run("should return total vulns by severity", func(t *testing.T) {
		analysis := &Analysis{
			Vulnerabilities: []Vulnerability{
				{Severity: severity.Low},
				{Severity: severity.Low},
				{Severity: severity.Audit},
				{Severity: severity.Medium},
				{Severity: severity.High},
				{Severity: severity.High},
			},
		}

		assert.Equal(t, 2, analysis.GetTotalVulnerabilitiesBySeverity()[severity.Low])
		assert.Equal(t, 1, analysis.GetTotalVulnerabilitiesBySeverity()[severity.Medium])
		assert.Equal(t, 2, analysis.GetTotalVulnerabilitiesBySeverity()[severity.High])
		assert.Equal(t, 1, analysis.GetTotalVulnerabilitiesBySeverity()[severity.Audit])
		assert.Equal(t, 0, analysis.GetTotalVulnerabilitiesBySeverity()[severity.NoSec])
		assert.Equal(t, 0, analysis.GetTotalVulnerabilitiesBySeverity()[severity.Info])
	})
}

func TestSortVulnerabilitiesByCriticality(t *testing.T) {
	t.Run("should return total of 1 vulnerability", func(t *testing.T) {
		analysis := &Analysis{
			Vulnerabilities: []Vulnerability{
				{Severity: severity.Low},
				{Severity: severity.Medium},
				{Severity: severity.High},
			},
		}

		analysis.SortVulnerabilitiesByCriticality()

		assert.Equal(t, severity.High, analysis.Vulnerabilities[0].Severity)
		assert.Equal(t, severity.Medium, analysis.Vulnerabilities[1].Severity)
		assert.Equal(t, severity.Low, analysis.Vulnerabilities[2].Severity)
	})
}

func TestSetAnalysisIDAndNewIDInVulnerabilities(t *testing.T) {
	t.Run("vulnerabilities id and analysis id should not be nil", func(t *testing.T) {
		analysis := &Analysis{
			ID:              uuid.New(),
			Vulnerabilities: []Vulnerability{{}},
		}

		analysis.SetAnalysisIDAndNewIDInVulnerabilities()
		for _, item := range analysis.Vulnerabilities {
			assert.NotEqual(t, uuid.Nil, item.VulnerabilityID)
			assert.NotEqual(t, uuid.Nil, item.AnalysisID)
		}
	})
}
