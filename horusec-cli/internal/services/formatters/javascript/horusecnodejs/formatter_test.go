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

package horusecnodejs

import (
	"errors"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	cliConfig "github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/ZupIT/horusec/horusec-cli/internal/entities/workdir"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"github.com/stretchr/testify/assert"
)

func TestParseOutputHorusecNodeJS(t *testing.T) {
	t.Run("HorusecNodeJS Should not return panic and but append errors found in analysis", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("DeleteContainersFromAPI")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

		assert.NotPanics(t, func() {
			NewFormatter(service).StartAnalysis("")
			assert.Equal(t, len(analysis.AnalysisVulnerabilities), 0)
			assert.NotEqual(t, len(analysis.Errors), 0)
		})
	})
	t.Run("HorusecNodeJS Should not return panic and exists vulnerabilities when call start horusec nodejs", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		responseContainer := `
[
  {
    "ID": "1079260f-aea3-4d10-9b14-1a96d7043dad",
    "Name": "test vuln",
    "Severity": "HIGH",
    "CodeSample": "test code;",
    "Confidence": "LOW",
    "Description": "example description.",
    "SourceLocation": {
      "Filename": "test.js",
      "Line": 2,
      "Column": 7
    }
  }
]
`
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("DeleteContainersFromAPI")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(responseContainer, nil)

		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

		assert.NotPanics(t, func() {
			NewFormatter(service).StartAnalysis("")
			assert.NotEqual(t, len(analysis.AnalysisVulnerabilities), 0)
		})
	})
	t.Run("HorusecNodeJS Should return empty analysis when format is empty", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}

		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

		formatter := Formatter{
			service,
		}

		err := formatter.formatOutput("")
		assert.NoError(t, err)
		assert.Len(t, analysis.AnalysisVulnerabilities, 0)
	})
	t.Run("HorusecNodeJS Should return empty analysis when format is null", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}

		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

		formatter := Formatter{
			service,
		}

		err := formatter.formatOutput("null")
		assert.NoError(t, err)
		assert.Len(t, analysis.AnalysisVulnerabilities, 0)
	})
	t.Run("HorusecNodeJS Should return error when invalid output", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}

		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

		formatter := Formatter{
			service,
		}

		err := formatter.formatOutput("invalid output")
		assert.Error(t, err)
	})
	t.Run("Should not execute tool because it's ignored", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		config := &cliConfig.Config{}
		config.SetToolsToIgnore([]string{"gosec", "securitycodescan", "brakeman", "safety", "bandit", "npmaudit", "yarnaudit", "spotbugs", "horuseckotlin", "horusecjava", "horusecleaks", "horusecnodejs", "gitleaks", "tfsec", "semgrep"})

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}
