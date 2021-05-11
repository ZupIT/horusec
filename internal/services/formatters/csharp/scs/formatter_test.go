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
	"errors"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"testing"

	entitiesAnalysis "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec/internal/entities/monitor"

	"github.com/stretchr/testify/assert"

	cliConfig "github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/workdir"
	"github.com/ZupIT/horusec/internal/services/docker"
	"github.com/ZupIT/horusec/internal/services/formatters"
)

func TestParseOutput(t *testing.T) {
	t.Run("Should return 4 vulnerabilities with no errors", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		analysis := &entitiesAnalysis.Analysis{}
		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})

		output := "{\"Filename\": \"Vulnerabilities.cs(11,22)\", \"IssueSeverity\": \"test\", \"ErrorID\": \"SCS1234\", \"IssueText\": \"test/[/src/test\"}" +
			"{\"Filename\": \"Vulnerabilities.cs(33,44)\", \"IssueSeverity\": \"test\", \"ErrorID\": \"SCS0021\", \"IssueText\": \"test\"}" +
			"{\"Filename\": \"Vulnerabilities.cs(55,66)\", \"IssueSeverity\": \"test\", \"ErrorID\": \"SCS0012\", \"IssueText\": \"test\"}" +
			"{\"Filename\": \"Vulnerabilities.cs(77,88)\", \"IssueSeverity\": \"test\", \"ErrorID\": \"SCS0020\", \"IssueText\": \"test\"}" +
			"{\"Filename\": \"Vulnerabilities.cs(11,22)\", \"IssueSeverity\": \"test\", \"ErrorID\": \"SCS1234\", \"IssueText\": \"test\"}" +
			"{\"Filename\": \"Vulnerabilities.cs(33,44)\", \"IssueSeverity\": \"test\", \"ErrorID\": \"SCS0021\", \"IssueText\": \"test\"}" +
			"{\"Filename\": \"Vulnerabilities.cs(55,66)\", \"IssueSeverity\": \"test\", \"ErrorID\": \"SCS0012\", \"IssueText\": \"test\"}" +
			"{\"Filename\": \"Vulnerabilities.cs(77,88)\", \"IssueSeverity\": \"test\", \"ErrorID\": \"SCS0020\", \"IssueText\": \"test\"}"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &monitor.Monitor{})
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.Len(t, analysis.AnalysisVulnerabilities, 4)
	})

	t.Run("Should error not found cs proj", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})

		output := "Specify a project or solution file"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &monitor.Monitor{})
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.NotEmpty(t, analysis.Errors)
	})

	t.Run("Should error executing container", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &monitor.Monitor{})
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
		assert.NotEmpty(t, analysis.Errors)
	})

	t.Run("Should not execute tool because it's ignored", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})
		config.SetToolsConfig(toolsconfig.ToolsConfigsStruct{SecurityCodeScan: toolsconfig.ToolConfig{IsToIgnore: true}})

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &monitor.Monitor{})
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}

func TestParseStringToStruct(t *testing.T) {
	t.Run("Should return error when unmarshall a invalid data", func(t *testing.T) {
		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})

		service := formatters.NewFormatterService(&entitiesAnalysis.Analysis{}, nil, config, &monitor.Monitor{})

		formatter := Formatter{
			service,
		}

		_, err := formatter.parseStringToStruct("!!!")
		assert.Error(t, err)
	})
}
