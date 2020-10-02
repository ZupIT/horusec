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

package scs

import (
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	cliConfig "github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/ZupIT/horusec/horusec-cli/internal/entities/workdir"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"github.com/stretchr/testify/assert"
)

func TestParseOutput(t *testing.T) {
	t.Run("Should return 4 vulnerabilities with no errors", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		analysis := &horusec.Analysis{}
		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		output := "{\"Filename\": \"Vulnerabilities.cs(11,22)\", \"IssueSeverity\": \"test\", \"ErrorID\": \"SCS1234\", \"IssueText\": \"test\"}" +
			"{\"Filename\": \"Vulnerabilities.cs(33,44)\", \"IssueSeverity\": \"test\", \"ErrorID\": \"SCS0021\", \"IssueText\": \"test\"}" +
			"{\"Filename\": \"Vulnerabilities.cs(55,66)\", \"IssueSeverity\": \"test\", \"ErrorID\": \"SCS0012\", \"IssueText\": \"test\"}" +
			"{\"Filename\": \"Vulnerabilities.cs(77,88)\", \"IssueSeverity\": \"test\", \"ErrorID\": \"SCS0020\", \"IssueText\": \"test\"}" +
			"{\"Filename\": \"Vulnerabilities.cs(11,22)\", \"IssueSeverity\": \"test\", \"ErrorID\": \"SCS1234\", \"IssueText\": \"test\"}" +
			"{\"Filename\": \"Vulnerabilities.cs(33,44)\", \"IssueSeverity\": \"test\", \"ErrorID\": \"SCS0021\", \"IssueText\": \"test\"}" +
			"{\"Filename\": \"Vulnerabilities.cs(55,66)\", \"IssueSeverity\": \"test\", \"ErrorID\": \"SCS0012\", \"IssueText\": \"test\"}" +
			"{\"Filename\": \"Vulnerabilities.cs(77,88)\", \"IssueSeverity\": \"test\", \"ErrorID\": \"SCS0020\", \"IssueText\": \"test\"}"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.Len(t, analysis.AnalysisVulnerabilities, 4)
	})

	t.Run("Should error not found cs proj", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		output := "Could not find any project in test"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.NotEmpty(t, analysis.Errors)
	})
}

func TestParseStringToStruct(t *testing.T) {
	t.Run("Should return error when unmarshall a invalid data", func(t *testing.T) {
		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		service := formatters.NewFormatterService(&horusec.Analysis{}, nil, config, &horusec.Monitor{})

		formatter := Formatter{
			service,
		}

		_, err := formatter.parseStringToStruct("!!!")
		assert.Error(t, err)
	})
}
