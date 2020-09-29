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

package formatters

import (
	"errors"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/horusec-cli/config"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/entities/workdir"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/docker"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestExecuteContainer(t *testing.T) {
	t.Run("should return no error when success set is finished", func(t *testing.T) {
		analysis := &horusec.Analysis{}

		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("test", nil)

		monitorController := NewFormatterService(analysis, dockerAPIControllerMock, &config.Config{}, &horusec.Monitor{})
		result, err := monitorController.ExecuteContainer(&dockerEntities.AnalysisData{})

		assert.NoError(t, err)
		assert.Equal(t, "test", result)
	})
}

func TestGetAnalysisIDErrorMessage(t *testing.T) {
	t.Run("should success get error message with replaces", func(t *testing.T) {
		monitorController := NewFormatterService(&horusec.Analysis{}, &docker.Mock{}, &config.Config{}, &horusec.Monitor{})

		result := monitorController.GetAnalysisIDErrorMessage(tools.Bandit, "test")

		assert.NotEmpty(t, result)
		assert.Equal(t, "{HORUSEC_CLI} Something error went wrong in Bandit tool"+
			" | analysisID -> 00000000-0000-0000-0000-000000000000 | output -> test", result)
	})
}

func TestGetCommitAuthor(t *testing.T) {
	t.Run("should get commit author", func(t *testing.T) {
		monitorController := NewFormatterService(&horusec.Analysis{}, &docker.Mock{}, &config.Config{}, &horusec.Monitor{})

		result := monitorController.GetCommitAuthor("", "")

		assert.NotEmpty(t, result)
	})
}

func TestGetConfigProjectPath(t *testing.T) {
	t.Run("should success get project path", func(t *testing.T) {
		cliConfig := &config.Config{}
		cliConfig.SetProjectPath("test")

		monitorController := NewFormatterService(&horusec.Analysis{}, &docker.Mock{}, cliConfig, &horusec.Monitor{})

		result := monitorController.GetConfigProjectPath()

		assert.NotEmpty(t, result)
		assert.Equal(t, "test", result)
	})
}

func TestAddWorkDirInCmd(t *testing.T) {
	t.Run("should success add workdir with no errors", func(t *testing.T) {
		cliConfig := &config.Config{}
		cliConfig.WorkDir = &workdir.WorkDir{}
		cliConfig.WorkDir.NetCore = []string{"test"}

		monitorController := NewFormatterService(&horusec.Analysis{}, &docker.Mock{}, cliConfig, &horusec.Monitor{})

		result := monitorController.AddWorkDirInCmd("test", "C#")

		assert.NotEmpty(t, result)
	})

	t.Run("should return cmd with no workdir", func(t *testing.T) {
		cliConfig := &config.Config{}
		cliConfig.WorkDir = &workdir.WorkDir{}

		monitorController := NewFormatterService(&horusec.Analysis{}, &docker.Mock{}, cliConfig, &horusec.Monitor{})

		result := monitorController.AddWorkDirInCmd("test", "C#")

		assert.NotEmpty(t, result)
	})
}

func TestLogDebugWithReplace(t *testing.T) {
	t.Run("should log debug and not panics", func(t *testing.T) {
		monitorController := NewFormatterService(&horusec.Analysis{}, &docker.Mock{}, &config.Config{}, &horusec.Monitor{})

		assert.NotPanics(t, func() {
			monitorController.LogDebugWithReplace("test", tools.NpmAudit)
		})
	})
}

func TestGetAnalysisID(t *testing.T) {
	t.Run("should success get analysis id", func(t *testing.T) {
		id := uuid.New()
		monitorController := NewFormatterService(&horusec.Analysis{ID: id}, &docker.Mock{}, &config.Config{}, &horusec.Monitor{})
		assert.Equal(t, id.String(), monitorController.GetAnalysisID())
	})
}

func TestGetAnalysis(t *testing.T) {
	t.Run("should success get analysis", func(t *testing.T) {
		id := uuid.New()
		monitorController := NewFormatterService(&horusec.Analysis{ID: id}, &docker.Mock{}, &config.Config{}, &horusec.Monitor{})
		assert.NotEmpty(t, monitorController.GetAnalysis())
	})
}

func TestSetAnalysisError(t *testing.T) {
	t.Run("should success set analysis errors", func(t *testing.T) {
		monitorController := NewFormatterService(&horusec.Analysis{}, &docker.Mock{}, &config.Config{}, &horusec.Monitor{})

		monitorController.SetAnalysisError(errors.New("test"))

		assert.NotEmpty(t, monitorController.GetAnalysis().Errors)
	})
}

func TestLogAnalysisError(t *testing.T) {
	t.Run("should not panic when logging error", func(t *testing.T) {
		monitorController := NewFormatterService(&horusec.Analysis{}, &docker.Mock{}, &config.Config{}, &horusec.Monitor{})

		assert.NotPanics(t, func() {
			monitorController.LogAnalysisError(errors.New("test"), tools.GoSec, "")
		})
	})
	t.Run("should not panic when logging error and exists projectSubPath", func(t *testing.T) {
		monitorController := NewFormatterService(&horusec.Analysis{}, &docker.Mock{}, &config.Config{}, &horusec.Monitor{})

		assert.NotPanics(t, func() {
			monitorController.LogAnalysisError(errors.New("test"), tools.GoSec, "/tmp")
		})
	})
}

func TestSetLanguageIsFinished(t *testing.T) {
	t.Run("should set go as finished", func(t *testing.T) {
		monitor := horusec.NewMonitor()
		monitor.AddProcess(1)

		monitorController := NewFormatterService(&horusec.Analysis{}, &docker.Mock{}, &config.Config{}, nil)
		monitorController.SetMonitor(monitor)

		monitorController.SetLanguageIsFinished()
		assert.Equal(t, 0, monitor.GetProcess())
	})
}
