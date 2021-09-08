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
	"github.com/ZupIT/horusec/internal/utils/mock"

	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec/config"
)

func TestStartPrintResultsMock(t *testing.T) {
	t.Run("Should return correctly mock", func(t *testing.T) {
		m := &Mock{}
		m.On("StartPrintResults").Return(0, nil)

		totalVulns, err := m.Print()
		assert.NoError(t, err)
		assert.Equal(t, 0, totalVulns)
	})
}

func TestPrintResults_StartPrintResults(t *testing.T) {
	t.Run("Should not return errors with type TEXT", func(t *testing.T) {
		configs := &config.Config{}

		analysis := &entitiesAnalysis.Analysis{
			AnalysisVulnerabilities: []entitiesAnalysis.AnalysisVulnerabilities{},
		}

		totalVulns, err := NewPrintResults(analysis, configs).Print()

		assert.NoError(t, err)
		assert.Equal(t, 0, totalVulns)
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

		totalVulns, err := printResults.Print()
		assert.NoError(t, err)
		assert.Equal(t, 0, totalVulns)
	})

	t.Run("Should return not errors because exists error in analysis", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{
			Errors: "Exists an error when read analysis",
		}

		configs := &config.Config{}
		configs.PrintOutputType = "JSON"

		totalVulns, err := NewPrintResults(analysis, configs).Print()

		assert.NoError(t, err)
		assert.Equal(t, 0, totalVulns)
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

		_, err := printResults.Print()

		assert.Error(t, err)
	})

	t.Run("Should return 12 vulnerabilities with timeout occurs", func(t *testing.T) {
		analysisMock := mock.CreateAnalysisMock()

		analysisMock.AnalysisVulnerabilities = append(analysisMock.AnalysisVulnerabilities, entitiesAnalysis.AnalysisVulnerabilities{Vulnerability: mock.CreateAnalysisMock().AnalysisVulnerabilities[0].Vulnerability})
		configs := &config.Config{}
		configs.IsTimeout = true
		printResults := &PrintResults{
			analysis: analysisMock,
			configs:  configs,
		}

		totalVulns, err := printResults.Print()

		assert.NoError(t, err)
		assert.Equal(t, 12, totalVulns)
	})

	t.Run("Should return 12 vulnerabilities", func(t *testing.T) {
		analysisMock := mock.CreateAnalysisMock()

		analysisMock.AnalysisVulnerabilities = append(analysisMock.AnalysisVulnerabilities, entitiesAnalysis.AnalysisVulnerabilities{Vulnerability: mock.CreateAnalysisMock().AnalysisVulnerabilities[0].Vulnerability})

		printResults := &PrintResults{
			analysis: analysisMock,
			configs:  &config.Config{},
		}

		totalVulns, err := printResults.Print()

		assert.NoError(t, err)
		assert.Equal(t, 12, totalVulns)
	})

	t.Run("Should return 12 vulnerabilities with commit authors", func(t *testing.T) {
		configs := &config.Config{}
		configs.EnableCommitAuthor = true
		analysisMock := mock.CreateAnalysisMock()

		analysisMock.AnalysisVulnerabilities = append(analysisMock.AnalysisVulnerabilities, entitiesAnalysis.AnalysisVulnerabilities{Vulnerability: mock.CreateAnalysisMock().AnalysisVulnerabilities[0].Vulnerability})

		totalVulns, err := NewPrintResults(analysisMock, configs).Print()

		assert.NoError(t, err)
		assert.Equal(t, 12, totalVulns)
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

		totalVulns, err := printResults.Print()
		assert.NoError(t, err)
		assert.Equal(t, 1, totalVulns)
	})
}
