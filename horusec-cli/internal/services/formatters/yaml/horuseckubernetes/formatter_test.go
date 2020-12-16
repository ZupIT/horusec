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

package horuseckubernetes

import (
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/config"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"github.com/stretchr/testify/assert"
)

func TestStartAnalysis(t *testing.T) {
	t.Run("should success execute analysis without errors", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		service := &formatters.Mock{}

		service.On("LogDebugWithReplace")
		service.On("SetToolFinishedAnalysis")
		service.On("LogAnalysisError")
		service.On("ToolIsToIgnore").Return(false)
		service.On("GetEngineConfig").Return(config.NewConfig())
		service.On("ParseFindingsToVulnerabilities").Return(nil)

		assert.NotPanics(t, func() {
			NewFormatter(service).StartAnalysis("")
		})

		assert.Empty(t, len(analysis.Errors))
	})

	t.Run("should ignore this tool", func(t *testing.T) {
		service := &formatters.Mock{}

		service.On("ToolIsToIgnore").Return(true)

		assert.NotPanics(t, func() {
			NewFormatter(service).StartAnalysis("")
		})
	})
}
