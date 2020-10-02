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

package printresults

import (
	"errors"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/test"
	"github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/stretchr/testify/assert"
)

func TestStartPrintResultsMock(t *testing.T) {
	t.Run("Should return correctly mock", func(t *testing.T) {
		m := &Mock{}
		m.On("StartPrintResults").Return(0, nil)

		totalVulns, err := m.StartPrintResults()
		assert.NoError(t, err)
		assert.Equal(t, 0, totalVulns)
	})
}

func TestPrintResults_StartPrintResults(t *testing.T) {
	t.Run("Should not return errors with type TEXT", func(t *testing.T) {
		configs := &config.Config{}

		analysis := &horusec.Analysis{
			AnalysisVulnerabilities: []horusec.AnalysisVulnerabilities{},
		}

		totalVulns, err := NewPrintResults(analysis, configs).StartPrintResults()

		assert.NoError(t, err)
		assert.Equal(t, 0, totalVulns)
	})

	t.Run("Should not return errors with type JSON", func(t *testing.T) {
		analysis := &horusec.Analysis{
			AnalysisVulnerabilities: []horusec.AnalysisVulnerabilities{},
		}

		configs := &config.Config{}
		configs.JSONOutputFilePath = "/tmp/horusec.json"

		printResults := &PrintResults{
			analysis: analysis,
			configs:  configs,
		}

		totalVulns, err := printResults.StartPrintResults()
		assert.NoError(t, err)
		assert.Equal(t, 0, totalVulns)
	})

	t.Run("Should return not errors because exists error in analysis", func(t *testing.T) {
		analysis := &horusec.Analysis{
			Errors: "Exists an error when read analysis",
		}

		configs := &config.Config{}
		configs.PrintOutputType = "JSON"

		totalVulns, err := NewPrintResults(analysis, configs).StartPrintResults()

		assert.NoError(t, err)
		assert.Equal(t, 0, totalVulns)
	})

	t.Run("Should return errors with type JSON", func(t *testing.T) {
		analysis := test.CreateAnalysisMock()

		analysis.SetAnalysisError(errors.New("ERROR GET REPOSITORY"))

		configs := &config.Config{}
		configs.PrintOutputType = "json"

		printResults := &PrintResults{
			analysis: analysis,
			configs:  configs,
		}

		_, err := printResults.StartPrintResults()

		assert.Error(t, err)
	})

	t.Run("Should return 12 vulnerabilities", func(t *testing.T) {
		analysis := test.CreateAnalysisMock()

		analysis.AnalysisVulnerabilities = append(analysis.AnalysisVulnerabilities, horusec.AnalysisVulnerabilities{Vulnerability: test.GetGoVulnerabilityWithSeverity(severity.Low)})

		printResults := &PrintResults{
			analysis: analysis,
			configs:  &config.Config{},
		}

		totalVulns, err := printResults.StartPrintResults()

		assert.NoError(t, err)
		assert.Equal(t, 12, totalVulns)
	})

	t.Run("Should return 12 vulnerabilities", func(t *testing.T) {
		configs := &config.Config{}

		analysis := test.CreateAnalysisMock()

		analysis.AnalysisVulnerabilities = append(analysis.AnalysisVulnerabilities, horusec.AnalysisVulnerabilities{Vulnerability: test.GetGoVulnerabilityWithSeverity(severity.Medium)})

		totalVulns, err := NewPrintResults(analysis, configs).StartPrintResults()

		assert.NoError(t, err)
		assert.Equal(t, 12, totalVulns)
	})

	t.Run("Should not return errors when configured to ignore vulnerabilities with severity LOW and MEDIUM", func(t *testing.T) {
		analysis := test.CreateAnalysisMock()

		analysis.AnalysisVulnerabilities = []horusec.AnalysisVulnerabilities{
			{
				Vulnerability: test.GetGoVulnerabilityWithSeverity(severity.Medium),
			},
			{
				Vulnerability: test.GetGoVulnerabilityWithSeverity(severity.Low),
			},
			{
				Vulnerability: test.GetGoVulnerabilityWithSeverity(severity.High),
			},
		}

		configs := &config.Config{}
		configs.TypesOfVulnerabilitiesToIgnore = "MEDIUM, LOW"

		printResults := &PrintResults{
			analysis: analysis,
			configs:  configs,
		}

		totalVulns, err := printResults.StartPrintResults()
		assert.NoError(t, err)
		assert.Equal(t, 1, totalVulns)
	})
}
