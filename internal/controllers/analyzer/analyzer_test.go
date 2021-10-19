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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ZupIT/horusec/internal/utils/testutil"

	"github.com/ZupIT/horusec-devkit/pkg/entities/cli"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	entitiesAnalysis "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	vulnerabilityenum "github.com/ZupIT/horusec-devkit/pkg/enums/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	horusecAPI "github.com/ZupIT/horusec/internal/services/horusec_api"
	"github.com/ZupIT/horusec/internal/utils/mock"
	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"

	"github.com/ZupIT/horusec/internal/entities/workdir"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec/config"
	languageDetect "github.com/ZupIT/horusec/internal/controllers/language_detect"
	"github.com/ZupIT/horusec/internal/controllers/printresults"
	"github.com/ZupIT/horusec/internal/services/docker"
	dockerClient "github.com/ZupIT/horusec/internal/services/docker/client"
	"github.com/ZupIT/horusec/internal/services/formatters"
)

func BenchmarkAnalyzerAnalyze(b *testing.B) {
	b.ReportAllocs()

	logger.LogSetOutput(io.Discard)
	// Hack to not print analysis result and make benchmark clean
	_, w, _ := os.Pipe()
	os.Stdout = w

	cfg := config.New()
	cfg.ProjectPath = testutil.GoExample
	analyzer := NewAnalyzer(cfg)

	for i := 0; i < b.N; i++ {
		if _, err := analyzer.Analyze(); err != nil {
			b.Fatalf("Unexepcted error to analyze on benchmark: %v\n", err)
		}
	}
}

func TestAnalyzerSetFalsePositivesAndRiskAcceptInVulnerabilities(t *testing.T) {
	vuln := vulnerability.Vulnerability{
		RuleID:  "HS-TEST-1",
		Line:    "10",
		Column:  "20",
		File:    "testing",
		Code:    "testing",
		Details: fmt.Sprintf("Test\nDescription testing"),
	}
	vulnhash.Bind(&vuln)

	testcases := []struct {
		name          string
		vulnerability vulnerability.Vulnerability
		hashes        []string
		expectedType  vulnerabilityenum.Type
	}{
		{
			name:          "ChangeCorrectHashToFalsePositive",
			vulnerability: vuln,
			hashes:        []string{vuln.VulnHash},
			expectedType:  vulnerabilityenum.FalsePositive,
		},
		{
			name:          "ChangeBreakingHashToFalsePositive",
			vulnerability: vuln,
			hashes:        []string{vuln.VulnHashInvalid},
			expectedType:  vulnerabilityenum.FalsePositive,
		},
		{
			name:          "ChangeCorrectHashToRiskAccept",
			vulnerability: vuln,
			hashes:        []string{vuln.VulnHash},
			expectedType:  vulnerabilityenum.RiskAccepted,
		},
		{
			name:          "ChangeBreakingHashToRiskAccept",
			vulnerability: vuln,
			hashes:        []string{vuln.VulnHashInvalid},
			expectedType:  vulnerabilityenum.RiskAccepted,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := NewAnalyzer(config.New())

			analyzer.analysis.AnalysisVulnerabilities = append(
				analyzer.analysis.AnalysisVulnerabilities, analysis.AnalysisVulnerabilities{
					AnalysisID:    uuid.New(),
					Vulnerability: tt.vulnerability,
				},
			)
			var (
				falsePositiveHashes []string
				riskAcceptHashes    []string
			)

			switch tt.expectedType {
			case vulnerabilityenum.FalsePositive:
				falsePositiveHashes = tt.hashes
			case vulnerabilityenum.RiskAccepted:
				riskAcceptHashes = tt.hashes
			default:
				t.Fatalf("invalid type %s", tt.expectedType)
			}

			analyzer.SetFalsePositivesAndRiskAcceptInVulnerabilities(falsePositiveHashes, riskAcceptHashes)

			require.Len(t, analyzer.analysis.AnalysisVulnerabilities, len(tt.hashes))
			for _, vuln := range analyzer.analysis.AnalysisVulnerabilities {
				assert.Equal(t, tt.expectedType, vuln.Vulnerability.Type)
			}

		})
	}
}

func TestNewAnalyzer(t *testing.T) {
	t.Run("Should return type os struct correctly", func(t *testing.T) {
		assert.IsType(t, &Analyzer{}, NewAnalyzer(&config.Config{}))
	})
}

func TestAnalyzerWithoutMock(t *testing.T) {
	t.Run("Should run all analysis with no timeout and error", func(t *testing.T) {
		cfg := config.New()

		cfg.ProjectPath = testutil.GoExample
		controller := NewAnalyzer(cfg)
		_, err := controller.Analyze()
		assert.NoError(t, err)
	})
	t.Run("Should run all analysis with and send to server correctly", func(t *testing.T) {
		cfg := config.New()

		cfg.ProjectPath = testutil.GoExample
		cfg.RepositoryAuthorization = "1234"

		handlerFunc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			structToValidate := &cli.AnalysisData{}
			cliVersion := r.Header.Get("X-Horusec-CLI-Version")
			authorization := r.Header.Get("X-Horusec-Authorization")
			byteArray, err := io.ReadAll(r.Body)
			assert.Nil(t, err)
			err = json.Unmarshal(byteArray, &structToValidate)
			assert.Nil(t, err)
			assert.Equal(t, cfg.RepositoryAuthorization, authorization)
			assert.Equal(t, cfg.Version, cliVersion)
		})

		router := http.NewServeMux()
		router.HandleFunc("/api/analysis", handlerFunc)
		svr := httptest.NewServer(router)
		cfg.HorusecAPIUri = svr.URL
		defer svr.Close()

		controller := NewAnalyzer(cfg)
		_, err := controller.Analyze()
		assert.NoError(t, err)
	})
}

func TestAnalyzer_AnalysisDirectory(t *testing.T) {
	t.Run("Should run all analysis with no timeout and error", func(t *testing.T) {
		configs := config.New()
		configs.WorkDir = &workdir.WorkDir{Go: []string{"test"}}
		configs.EnableCommitAuthor = true
		configs.EnableGitHistoryAnalysis = true
		configs.FalsePositiveHashes = []string{"test"}

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
		dockerMocker.On("ImagePull").Return(io.NopCloser(bytes.NewReader([]byte(""))), nil)
		dockerMocker.On("ContainerCreate").Return(container.ContainerCreateCreatedBody{}, nil)
		dockerMocker.On("ContainerStart").Return(nil)
		dockerMocker.On("ContainerWait").Return(container.ContainerWaitOKBody{}, nil)
		dockerMocker.On("ContainerLogs").Return(io.NopCloser(bytes.NewReader([]byte(""))), nil)
		dockerMocker.On("ContainerRemove").Return(nil)
		dockerMocker.On("ContainerList").Return([]types.Container{{ID: "test"}}, nil)

		dockerSDK := docker.New(dockerMocker, configs, uuid.New())

		controller := &Analyzer{
			docker:          dockerSDK,
			config:          configs,
			languageDetect:  languageDetectMock,
			printController: printResultMock,
			horusec:         horusecAPIMock,
			formatter:       formatters.NewFormatterService(&entitiesAnalysis.Analysis{}, dockerSDK, configs),
			loading:         newScanLoading(),
		}

		controller.analysis = &entitiesAnalysis.Analysis{ID: uuid.New()}
		totalVulns, err := controller.Analyze()
		assert.NoError(t, err)
		assert.Equal(t, 0, totalVulns)
	})
	t.Run("Should run all analysis with and send to server correctly", func(t *testing.T) {
		configs := config.New()
		configs.WorkDir = &workdir.WorkDir{Go: []string{"test"}}
		configs.FalsePositiveHashes = []string{"test"}

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
		dockerMocker.On("ImagePull").Return(io.NopCloser(bytes.NewReader([]byte(""))), nil)
		dockerMocker.On("ContainerCreate").Return(container.ContainerCreateCreatedBody{}, nil)
		dockerMocker.On("ContainerStart").Return(nil)
		dockerMocker.On("ContainerWait").Return(container.ContainerWaitOKBody{}, nil)
		dockerMocker.On("ContainerLogs").Return(io.NopCloser(bytes.NewReader([]byte(""))), nil)
		dockerMocker.On("ContainerRemove").Return(nil)
		dockerMocker.On("ContainerList").Return([]types.Container{{ID: "test"}}, nil)

		dockerSDK := docker.New(dockerMocker, configs, uuid.New())

		controller := &Analyzer{
			docker:          dockerSDK,
			config:          configs,
			languageDetect:  languageDetectMock,
			printController: printResultMock,
			horusec:         horusecAPIMock,
			formatter:       formatters.NewFormatterService(&entitiesAnalysis.Analysis{}, dockerSDK, configs),
			loading:         newScanLoading(),
		}

		controller.analysis = &entitiesAnalysis.Analysis{ID: uuid.New()}
		totalVulns, err := controller.Analyze()
		assert.NoError(t, err)
		assert.Equal(t, 0, totalVulns)
	})
	t.Run("Should run error in language detect", func(t *testing.T) {
		configs := config.New()
		configs.WorkDir = &workdir.WorkDir{}

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
		dockerMocker.On("ImagePull").Return(io.NopCloser(bytes.NewReader([]byte(""))), nil)
		dockerMocker.On("ContainerCreate").Return(container.ContainerCreateCreatedBody{}, nil)
		dockerMocker.On("ContainerStart").Return(nil)
		dockerMocker.On("ContainerWait").Return(container.ContainerWaitOKBody{}, nil)
		dockerMocker.On("ContainerLogs").Return(io.NopCloser(bytes.NewReader([]byte(""))), nil)
		dockerMocker.On("ContainerRemove").Return(nil)
		dockerMocker.On("ContainerList").Return([]types.Container{{ID: "test"}}, nil)

		dockerSDK := docker.New(dockerMocker, configs, uuid.New())

		controller := &Analyzer{
			docker:          dockerSDK,
			config:          configs,
			languageDetect:  languageDetectMock,
			printController: printResultMock,
			horusec:         horusecAPIMock,
			formatter:       formatters.NewFormatterService(&entitiesAnalysis.Analysis{}, dockerSDK, configs),
			loading:         newScanLoading(),
		}

		controller.analysis = &entitiesAnalysis.Analysis{ID: uuid.New()}
		totalVulns, err := controller.Analyze()
		assert.Error(t, err)
		assert.Equal(t, 0, totalVulns)
	})
}
