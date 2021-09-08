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

package bandit

import (
	"errors"
	"testing"
	"time"

	"github.com/ZupIT/horusec/internal/entities/toolsconfig"

	entitiesAnalysis "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	enumHorusec "github.com/ZupIT/horusec-devkit/pkg/enums/analysis"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	cliConfig "github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/workdir"
	"github.com/ZupIT/horusec/internal/services/docker"
	"github.com/ZupIT/horusec/internal/services/formatters"
)

func getAnalysis() *entitiesAnalysis.Analysis {
	return &entitiesAnalysis.Analysis{
		ID:                      uuid.New(),
		RepositoryID:            uuid.New(),
		WorkspaceID:             uuid.New(),
		Status:                  enumHorusec.Running,
		Errors:                  "",
		CreatedAt:               time.Now(),
		AnalysisVulnerabilities: []entitiesAnalysis.AnalysisVulnerabilities{},
	}
}

func TestNewFormatter(t *testing.T) {
	config := &cliConfig.Config{}
	config.WorkDir = &workdir.WorkDir{}

	service := formatters.NewFormatterService(nil, nil, config)

	assert.IsType(t, NewFormatter(service), &Formatter{})
}

func TestFormatter_StartSafety(t *testing.T) {
	t.Run("Should return error when start analysis", func(t *testing.T) {
		analysis := getAnalysis()

		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("Error"))

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})
	})

	t.Run("Should return analysis bandit without error", func(t *testing.T) {
		analysis := getAnalysis()

		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		output := `{"results": [{"code": "6 \n7 exec(command)\n8 \n","filename": "./main.py","line_number": 7,"issue_severity": "MEDIUM","issue_text": "Use of exec detected."}]}`
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})
	})

	t.Run("Should return analysis bandit without error", func(t *testing.T) {
		analysis := getAnalysis()

		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		output := `{"results": [{"code": "6 \n7 exec(command)\n8 \n","filename": "./main.py","line_number": 7,"issue_severity": "MEDIUM","issue_text": "Use of exec detected."}]}`
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})
	})

	t.Run("Should return analysis bandit without error with issue of informative", func(t *testing.T) {
		analysis := getAnalysis()

		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		output := `{"results": [{"issue_text": "Use of assert detected. The enclosed code will be removed when compiling to optimized byte code."}]}`
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})
	})

	t.Run("Should return nil when output is wrong format analysis", func(t *testing.T) {
		analysis := getAnalysis()

		config := &cliConfig.Config{}
		config.WorkDir = &workdir.WorkDir{}

		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("some aleatory text", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)

		formatter := NewFormatter(service)

		assert.NotPanics(t, func() {
			formatter.StartAnalysis("")
		})
	})
	t.Run("Should not execute tool because it's ignored", func(t *testing.T) {
		analysis := &entitiesAnalysis.Analysis{}
		dockerAPIControllerMock := &docker.Mock{}
		config := &cliConfig.Config{}
		config.ToolsConfig = toolsconfig.ParseInterfaceToMapToolsConfig(
			toolsconfig.ToolsConfigsStruct{Bandit: toolsconfig.ToolConfig{IsToIgnore: true}},
		)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}
