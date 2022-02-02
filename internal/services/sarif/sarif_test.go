// Copyright 2022 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package sarif

import (
	"testing"
	"time"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	analysisenum "github.com/ZupIT/horusec-devkit/pkg/enums/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestConvertVulnerabilityDataToSarif(t *testing.T) {
	t.Run("should successfully parse analysis to sarif output", func(t *testing.T) {
		entity := &analysis.Analysis{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			Status:    analysisenum.Success,
			AnalysisVulnerabilities: []analysis.AnalysisVulnerabilities{
				{
					Vulnerability: vulnerability.Vulnerability{
						Line:         "1",
						Column:       "1",
						Severity:     severities.High,
						File:         "sample.c",
						Code:         "assert(true == false);",
						Details:      "Universe failure; please restart reality",
						SecurityTool: tools.Bandit,
						Language:     languages.C,
					},
				},
			},
		}

		service := NewSarif(entity)

		result := service.ConvertVulnerabilityToSarif()
		assert.NotEmpty(t, result.Runs)
	})

	t.Run("field sets should be populated", func(t *testing.T) {
		analysis := &analysis.Analysis{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			Status:    analysisenum.Success,
			AnalysisVulnerabilities: []analysis.AnalysisVulnerabilities{
				{
					Vulnerability: vulnerability.Vulnerability{
						Line:         "1",
						Column:       "1",
						Severity:     severities.High,
						File:         "sample.c",
						Code:         "assert(true == false);",
						Details:      "Universe failure; please restart reality",
						SecurityTool: tools.Bandit,
						Language:     languages.C,
					},
				},
			},
		}

		service := NewSarif(analysis)

		result := service.ConvertVulnerabilityToSarif()
		assert.NotNil(t, result.Runs)
		assert.Len(t, result.Runs, 1)
		assert.Len(t, result.Runs[0].Results, 1)

		assert.EqualValues(t, result.Runs[0].Results[0].Message.Text, "Universe failure; please restart reality")

		assert.EqualValues(t, result.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI, "sample.c")

		assert.EqualValues(t, result.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.Snippet.Text, "assert(true == false);")
		assert.EqualValues(t, result.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.StartColumn, 1)
		assert.EqualValues(t, result.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.StartLine, 1)

		assert.NotNil(t, result.Runs[0].Tool)
		assert.EqualValues(t, result.Runs[0].Tool.Driver.Name, "Bandit")
	})
}
