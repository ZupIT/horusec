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

package analyser

import (
	"bytes"
	"errors"
	"io/ioutil"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/utils/test"

	"github.com/ZupIT/horusec/horusec-cli/internal/entities/workdir"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	analysisUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/analysis"
	"github.com/ZupIT/horusec/horusec-cli/config"
	languageDetect "github.com/ZupIT/horusec/horusec-cli/internal/controllers/language_detect"
	"github.com/ZupIT/horusec/horusec-cli/internal/controllers/printresults"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/docker"
	dockerClient "github.com/ZupIT/horusec/horusec-cli/internal/services/docker/client"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	horusecAPI "github.com/ZupIT/horusec/horusec-cli/internal/services/horusapi"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewAnalyser(t *testing.T) {
	t.Run("Should return type os struct correctly", func(t *testing.T) {
		assert.IsType(t, &Analyser{}, NewAnalyser(&config.Config{}))
	})
}

func TestAnalyser_AnalysisDirectory(t *testing.T) {
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
		horusecAPIMock.On("GetAnalysis").Return(&horusec.Analysis{}, nil)

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

		controller := &Analyser{
			dockerSDK:         dockerSDK,
			config:            configs,
			languageDetect:    languageDetectMock,
			analysisUseCases:  analysisUseCases.NewAnalysisUseCases(),
			printController:   printResultMock,
			horusecAPIService: horusecAPIMock,
			formatterService:  formatters.NewFormatterService(&horusec.Analysis{}, dockerSDK, configs, &horusec.Monitor{}),
		}

		controller.analysis = controller.analysisUseCases.NewAnalysisRunning()
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
		horusecAPIMock.On("GetAnalysis").Return(test.CreateAnalysisMock(), nil)

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

		controller := &Analyser{
			dockerSDK:         dockerSDK,
			config:            configs,
			languageDetect:    languageDetectMock,
			analysisUseCases:  analysisUseCases.NewAnalysisUseCases(),
			printController:   printResultMock,
			horusecAPIService: horusecAPIMock,
			formatterService:  formatters.NewFormatterService(&horusec.Analysis{}, dockerSDK, configs, &horusec.Monitor{}),
		}

		controller.analysis = controller.analysisUseCases.NewAnalysisRunning()
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
		horusecAPIMock.On("GetAnalysis").Return(&horusec.Analysis{}, nil)

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

		controller := &Analyser{
			dockerSDK:         dockerSDK,
			config:            configs,
			languageDetect:    languageDetectMock,
			analysisUseCases:  analysisUseCases.NewAnalysisUseCases(),
			printController:   printResultMock,
			horusecAPIService: horusecAPIMock,
			formatterService:  formatters.NewFormatterService(&horusec.Analysis{}, dockerSDK, configs, &horusec.Monitor{}),
		}

		controller.analysis = controller.analysisUseCases.NewAnalysisRunning()
		totalVulns, err := controller.AnalysisDirectory()
		assert.Error(t, err)
		assert.Equal(t, 0, totalVulns)
	})
}
