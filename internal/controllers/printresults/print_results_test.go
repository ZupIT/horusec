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
	"testing"

	entitiesAnalysis "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/utils/mock"

	"github.com/stretchr/testify/assert"
)

func TestStartPrintResultsMock(t *testing.T) {
	t.Run("Should return correctly mock", func(t *testing.T) {
		m := &Mock{}
		m.On("StartPrintResults").Return(0, false, nil)

		err := m.Print()
		assert.NoError(t, err)
	})
}

func TestPrintResults_StartPrintResults(t *testing.T) {
	t.Run("Should not return errors with type TEXT", func(t *testing.T) {
		configs := &config.Config{}

		analysis := &entitiesAnalysis.Analysis{
			AnalysisVulnerabilities: []entitiesAnalysis.AnalysisVulnerabilities{},
		}

		err := NewPrintResults(analysis, configs).Print()

		assert.NoError(t, err)
	})

	t.Run("Should not return errors with type JSON", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{
			AnalysisVulnerabilities: []entitiesAnalysis.AnalysisVulnerabilities{},
		}

		configs := &config.Config{}
		configs.JSONOutputFilePath = "/tmp/horusec.json"

		printResults := &PrintResults{
			analysis: analysis,
			configs:  configs,
		}

		err := printResults.Print()
		assert.NoError(t, err)
	})

	t.Run("Should return not errors because exists error in analysis", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{
			Errors: "Exists an error when read analysis",
		}

		configs := &config.Config{}
		configs.PrintOutputType = "JSON"

		err := NewPrintResults(analysis, configs).Print()

		assert.NoError(t, err)
	})

	t.Run("Should return errors with type JSON", func(t *testing.T) {
		analysis := mock.CreateAnalysisMock()

		analysis.Errors += "ERROR GET REPOSITORY"

		configs := &config.Config{}
		configs.PrintOutputType = "json"

		printResults := &PrintResults{
			analysis: analysis,
			configs:  configs,
		}

		err := printResults.Print()

		assert.Error(t, err)
	})

	t.Run("Should not return errors when configured to ignore vulnerabilities with severity LOW and MEDIUM", func(t *testing.T) {
		analysisMock := mock.CreateAnalysisMock()

		analysisMock.AnalysisVulnerabilities = []entitiesAnalysis.AnalysisVulnerabilities{
			{
				Vulnerability: mock.CreateAnalysisMock().AnalysisVulnerabilities[0].Vulnerability,
			},
			{
				Vulnerability: mock.CreateAnalysisMock().AnalysisVulnerabilities[1].Vulnerability,
			},
			{
				Vulnerability: mock.CreateAnalysisMock().AnalysisVulnerabilities[2].Vulnerability,
			},
		}

		configs := &config.Config{}
		configs.SeveritiesToIgnore = []string{"MEDIUM", "LOW"}

		printResults := &PrintResults{
			analysis: analysisMock,
			configs:  configs,
		}

		err := printResults.Print()
		assert.ErrorIs(t, err, ErrorUnknownVulnerabilitiesFound)
	})
}
