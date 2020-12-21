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

package horusecleaks

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

func TestParseOutputHorusecJava(t *testing.T) {
	t.Run("HorusecJava Should not return panic and but append errors found in analysis", func(t *testing.T) {
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
	t.Run("HorusecJava Should not return panic and exists vulnerabilities when call start horusec java", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		responseContainer := `
[
  {
    "ID": "b4c300cd-1cdd-4039-9b19-8163acd91bac",
    "Name": "Password found in a hardcoded URL",
    "Severity": "HIGH",
    "CodeSample": "postgresql://root:root@postgresql:5432/horusec_db?sslmode=disable;",
    "Confidence": "HIGH",
    "Description": "A password was found in a hardcoded URL, this can lead to not only the leak of this password but also a failure point to some more sophisticated CSRF and SSRF attacks. Check CWE-352 (https://cwe.mitre.org/data/definitions/352.html) and CWE-918 (https://cwe.mitre.org/data/definitions/918.html) for more details.",
    "SourceLocation": {
      "Filename": "deployments/docker-compose.dev.yaml",
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
	t.Run("HorusecJava Should return empty analysis when format is empty", func(t *testing.T) {
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
	t.Run("HorusecJava Should return empty analysis when format is null", func(t *testing.T) {
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
	t.Run("HorusecJava Should return error when invalid output", func(t *testing.T) {
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
		config.SetToolsToIgnore([]string{"GoSec", "SecurityCodeScan", "Brakeman", "Safety", "Bandit", "NpmAudit", "YarnAudit", "SpotBugs", "HorusecKotlin", "HorusecJava", "HorusecLeaks", "GitLeaks", "TfSec", "Semgrep", "HorusecCsharp", "HorusecKubernetes", "Eslint", "HorusecNodeJS", "Flawfinder", "PhpCS", "Eslint", "HorusecNodeJS", "Flawfinder", "PhpCS"})
		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}
