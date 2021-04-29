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

package sonarqube

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	enumHorusec "github.com/ZupIT/horusec-devkit/pkg/enums/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
)

func TestConvertVulnerabilityDataToSonarQube(t *testing.T) {
	t.Run("should success parse analysis to sonar output", func(t *testing.T) {
		entity := &analysis.Analysis{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			Status:    enumHorusec.Running,
			AnalysisVulnerabilities: []analysis.AnalysisVulnerabilities{
				{
					Vulnerability: vulnerability.Vulnerability{
						Line:     "1",
						Severity: severities.High,
					},
				},
			},
		}

		service := NewSonarQube(entity)

		result := service.ConvertVulnerabilityDataToSonarQube()
		assert.NotEmpty(t, result)
	})

	t.Run("issues should not be nil", func(t *testing.T) {
		analysis := &analysis.Analysis{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			Status:    enumHorusec.Running,
		}

		service := NewSonarQube(analysis)

		result := service.ConvertVulnerabilityDataToSonarQube()
		assert.NotNil(t, result.Issues)
	})
}
