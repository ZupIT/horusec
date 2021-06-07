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

package analyzer

import (
	"bytes"
	"errors"
	"io/ioutil"
	"testing"

	entitiesAnalysis "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec/internal/entities/monitor"
	horusecAPI "github.com/ZupIT/horusec/internal/services/horusec_api"
	"github.com/ZupIT/horusec/internal/utils/mock"

	"github.com/ZupIT/horusec/internal/entities/workdir"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec/config"
	languageDetect "github.com/ZupIT/horusec/internal/controllers/language_detect"
	"github.com/ZupIT/horusec/internal/controllers/printresults"
	"github.com/ZupIT/horusec/internal/services/docker"
	dockerClient "github.com/ZupIT/horusec/internal/services/docker/client"
	"github.com/ZupIT/horusec/internal/services/formatters"
)

func TestNewAnalyzer(t *testing.T) {
	t.Run("Should return type os struct correctly", func(t *testing.T) {
		assert.IsType(t, &Analyzer{}, NewAnalyzer(&config.Config{}))
	})
}

func TestAnalyzer_AnalysisDirectory(t *testing.T) {
	t.Run("Should run all analysis with no timeout and error", func(t *testing.T) {
		configs := &config.Config{}
		configs.SetWorkDir(&workdir.WorkDir{Go: []string{"test"}})
		configs.SetEnableCommitAuthor(true)
		configs.SetEnableGitHistoryAnalysis(true)
		configs.SetFalsePositiveHashes([]string{"test"})

		languageDetectMock := &languageDetect.Mock{}
		languageDetectMock.On("LanguageDetect").Return([]languages.Language{
			languages.Go,
			languages.CSharp,
			languages.Ruby,
			languages.Python,
			languages.Java,
			languages.Kotlin,
			languages.Javascript,
			languages.Leaks,
			languages.HCL,
			languages.Generic,
			languages.C,
			languages.PHP,
			languages.Yaml,
		}, nil)

		printResultMock := &printresults.Mock{}
		printResultMock.On("StartPrintResults").Return(0, nil)
		printResultMock.On("SetAnalysis")

		horusecAPIMock := &horusecAPI.Mock{}
		horusecAPIMock.On("SendAnalysis").Return(nil)
		horusecAPIMock.On("GetAnalysis").Return(&entitiesAnalysis.Analysis{}, nil)

		dockerMocker := &dockerClient.Mock{}
		dockerMocker.On("CreateLanguageAnalysisContainer").Return("", nil)
		dockerMocker.On("ImageList").Return([]types.ImageSummary{{}}, nil)
		dockerMocker.On("ImagePull").Return(ioutil.NopCloser(bytes.NewReader([]byte(""))), nil)
		dockerMocker.On("ContainerCreate").Return(container.ContainerCreateCreatedBody{}, nil)
		dockerMocker.On("ContainerStart").Return(nil)
		dockerMocker.On("ContainerWait").Return(container.ContainerWaitOKBody{}, nil)
		dockerMocker.On("ContainerLogs").Return(ioutil.NopCloser(bytes.NewReader([]byte(""))), nil)
		dockerMocker.On("ContainerRemove").Return(nil)
		dockerMocker.On("ContainerList").Return([]types.Container{{ID: "test"}}, nil)

		dockerSDK := docker.NewDockerAPI(dockerMocker, configs, uuid.New())

		controller := &Analyzer{
			dockerSDK:         dockerSDK,
			config:            configs,
			languageDetect:    languageDetectMock,
			printController:   printResultMock,
			horusecAPIService: horusecAPIMock,
			formatterService:  formatters.NewFormatterService(&entitiesAnalysis.Analysis{}, dockerSDK, configs, &monitor.Monitor{}),
		}

		controller.analysis = &entitiesAnalysis.Analysis{ID: uuid.New()}
		totalVulns, err := controller.AnalysisDirectory()
		assert.NoError(t, err)
		assert.Equal(t, 0, totalVulns)
	})
	t.Run("Should run all analysis with and send to server correctly", func(t *testing.T) {
		configs := &config.Config{}
		configs.SetWorkDir(&workdir.WorkDir{Go: []string{"test"}})
		configs.SetFalsePositiveHashes([]string{"test"})

		languageDetectMock := &languageDetect.Mock{}
		languageDetectMock.On("LanguageDetect").Return([]languages.Language{
			languages.Go,
			languages.CSharp,
			languages.Ruby,
			languages.Python,
			languages.Java,
			languages.Kotlin,
			languages.Javascript,
			languages.Leaks,
			languages.HCL,
			languages.Generic,
			languages.C,
			languages.PHP,
			languages.Yaml,
		}, nil)

		printResultMock := &printresults.Mock{}
		printResultMock.On("StartPrintResults").Return(0, nil)
		printResultMock.On("SetAnalysis")

		horusecAPIMock := &horusecAPI.Mock{}
		horusecAPIMock.On("SendAnalysis").Return(nil)
		horusecAPIMock.On("GetAnalysis").Return(mock.CreateAnalysisMock(), nil)

		dockerMocker := &dockerClient.Mock{}
		dockerMocker.On("CreateLanguageAnalysisContainer").Return("", nil)
		dockerMocker.On("ImageList").Return([]types.ImageSummary{{}}, nil)
		dockerMocker.On("ImagePull").Return(ioutil.NopCloser(bytes.NewReader([]byte(""))), nil)
		dockerMocker.On("ContainerCreate").Return(container.ContainerCreateCreatedBody{}, nil)
		dockerMocker.On("ContainerStart").Return(nil)
		dockerMocker.On("ContainerWait").Return(container.ContainerWaitOKBody{}, nil)
		dockerMocker.On("ContainerLogs").Return(ioutil.NopCloser(bytes.NewReader([]byte(""))), nil)
		dockerMocker.On("ContainerRemove").Return(nil)
		dockerMocker.On("ContainerList").Return([]types.Container{{ID: "test"}}, nil)

		dockerSDK := docker.NewDockerAPI(dockerMocker, configs, uuid.New())

		controller := &Analyzer{
			dockerSDK:         dockerSDK,
			config:            configs,
			languageDetect:    languageDetectMock,
			printController:   printResultMock,
			horusecAPIService: horusecAPIMock,
			formatterService:  formatters.NewFormatterService(&entitiesAnalysis.Analysis{}, dockerSDK, configs, &monitor.Monitor{}),
		}

		controller.analysis = &entitiesAnalysis.Analysis{ID: uuid.New()}
		totalVulns, err := controller.AnalysisDirectory()
		assert.NoError(t, err)
		assert.Equal(t, 0, totalVulns)
	})
	t.Run("Should run error in language detect", func(t *testing.T) {
		configs := &config.Config{}
		configs.SetWorkDir(&workdir.WorkDir{})

		languageDetectMock := &languageDetect.Mock{}
		languageDetectMock.On("LanguageDetect").Return([]languages.Language{}, errors.New("test"))

		printResultMock := &printresults.Mock{}
		printResultMock.On("StartPrintResults").Return(0, nil)
		printResultMock.On("SetAnalysis")

		horusecAPIMock := &horusecAPI.Mock{}
		horusecAPIMock.On("SendAnalysis").Return(nil)
		horusecAPIMock.On("GetAnalysis").Return(&entitiesAnalysis.Analysis{}, nil)

		dockerMocker := &dockerClient.Mock{}
		dockerMocker.On("CreateLanguageAnalysisContainer").Return("", nil)
		dockerMocker.On("ImageList").Return([]types.ImageSummary{{}}, nil)
		dockerMocker.On("ImagePull").Return(ioutil.NopCloser(bytes.NewReader([]byte(""))), nil)
		dockerMocker.On("ContainerCreate").Return(container.ContainerCreateCreatedBody{}, nil)
		dockerMocker.On("ContainerStart").Return(nil)
		dockerMocker.On("ContainerWait").Return(container.ContainerWaitOKBody{}, nil)
		dockerMocker.On("ContainerLogs").Return(ioutil.NopCloser(bytes.NewReader([]byte(""))), nil)
		dockerMocker.On("ContainerRemove").Return(nil)
		dockerMocker.On("ContainerList").Return([]types.Container{{ID: "test"}}, nil)

		dockerSDK := docker.NewDockerAPI(dockerMocker, configs, uuid.New())

		controller := &Analyzer{
			dockerSDK:         dockerSDK,
			config:            configs,
			languageDetect:    languageDetectMock,
			printController:   printResultMock,
			horusecAPIService: horusecAPIMock,
			formatterService:  formatters.NewFormatterService(&entitiesAnalysis.Analysis{}, dockerSDK, configs, &monitor.Monitor{}),
		}

		controller.analysis = &entitiesAnalysis.Analysis{ID: uuid.New()}
		totalVulns, err := controller.AnalysisDirectory()
		assert.Error(t, err)
		assert.Equal(t, 0, totalVulns)
	})
}
