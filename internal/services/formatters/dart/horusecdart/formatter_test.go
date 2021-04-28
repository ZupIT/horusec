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

package hrousecdart

import (
	"testing"

	entitiesAnalysis "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"

	"github.com/stretchr/testify/assert"

	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/internal/services/formatters"
)

func TestStartAnalysis(t *testing.T) {
	t.Run("should success execute analysis without errors", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}
		service := &formatters.Mock{}

		service.On("LogDebugWithReplace")
		service.On("SetToolFinishedAnalysis")
		service.On("SetAnalysisError")
		service.On("ToolIsToIgnore").Return(false)
		service.On("GetProjectPathWithWorkdir").Return(".")
		service.On("ParseFindingsToVulnerabilities").Return(nil)
		service.On("GetCustomRulesByLanguage").Return([]engine.Rule{})

		assert.NotPanics(t, func() {
			NewFormatter(service).StartAnalysis("")
		})

		assert.Empty(t, len(analysis.Errors))
	})

	t.Run("should return error when getting text unit", func(t *testing.T) {
		service := &formatters.Mock{}

		service.On("LogDebugWithReplace")
		service.On("SetToolFinishedAnalysis")
		service.On("SetAnalysisError")
		service.On("ToolIsToIgnore").Return(false)
		service.On("GetProjectPathWithWorkdir").Return("!!!")
		service.On("ParseFindingsToVulnerabilities").Return(nil)
		service.On("GetCustomRulesByLanguage").Return([]engine.Rule{})

		assert.NotPanics(t, func() {
			NewFormatter(service).StartAnalysis("")
		})
	})

	t.Run("should ignore this tool", func(t *testing.T) {
		service := &formatters.Mock{}

		service.On("ToolIsToIgnore").Return(true)

		assert.NotPanics(t, func() {
			NewFormatter(service).StartAnalysis("")
		})
	})
}
