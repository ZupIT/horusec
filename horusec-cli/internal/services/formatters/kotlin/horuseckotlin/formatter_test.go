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

package horuseckotlin

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

func TestParseOutputHorusecKotlin(t *testing.T) {
	t.Run("HorusecKotlin Should not return panic and but append errors found in analysis", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("DeleteContainersFromAPI")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

		assert.NotPanics(t, func() {
			NewFormatter(service).StartAnalysis("")
			assert.Equal(t, len(analysis.Vulnerabilities), 0)
			assert.NotEqual(t, len(analysis.Errors), 0)
		})
	})
	t.Run("HorusecKotlin Should not return panic and exists vulnerabilities when call start horusec java", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		responseContainer := `
[
  {
    "ID": "3dfb3624-e218-4e2b-a7e9-814b64aaa43e",
    "Name": "Hard-coded credentials",
    "Severity": "HIGH",
    "CodeSample": "val password = \"secret1234\"",
    "Confidence": "HIGH",
    "Description": "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data. For more information checkout the CWE-798 (https://cwe.mitre.org/data/definitions/798.html) advisory.",
    "SourceLocation": {
      "Filename": "/home/user/go/src/github.com/ZupIT/horusec/development-kit/pkg/engines/examples/kotlin-hardcodedpass/src/main/kotlin/Hello.kt",
      "Line": 148,
      "Column": 8
    }
  }
]
`
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("DeleteContainersFromAPI")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(responseContainer, nil)

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

		assert.NotPanics(t, func() {
			NewFormatter(service).StartAnalysis("")
			assert.NotEqual(t, len(analysis.Vulnerabilities), 0)
		})
	})
	t.Run("HorusecKotlin Should return empty analysis when format is empty", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

		formatter := Formatter{
			service,
		}

		err := formatter.formatOutput("")
		assert.NoError(t, err)
		assert.Len(t, analysis.Vulnerabilities, 0)
	})
	t.Run("HorusecKotlin Should return empty analysis when format is null", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

		formatter := Formatter{
			service,
		}

		err := formatter.formatOutput("null")
		assert.NoError(t, err)
		assert.Len(t, analysis.Vulnerabilities, 0)
	})
	t.Run("HorusecKotlin Should return error when invalid output", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

		formatter := Formatter{
			service,
		}

		err := formatter.formatOutput("invalid output")
		assert.Error(t, err)
	})
}
