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

package start

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"

	"github.com/ZupIT/horusec/internal/utils/testutil"

	"github.com/google/uuid"

	"github.com/ZupIT/horusec/internal/controllers/requirements"

	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/controllers/analyzer"
	"github.com/ZupIT/horusec/internal/entities/workdir"
	"github.com/ZupIT/horusec/internal/usecases/cli"
	"github.com/ZupIT/horusec/internal/utils/copy"
	"github.com/ZupIT/horusec/internal/utils/prompt"
)

var tmpPath, _ = filepath.Abs("tmp")

func TestMain(m *testing.M) {
	_ = os.RemoveAll(tmpPath)
	_ = os.MkdirAll(tmpPath, os.ModePerm)

	code := m.Run()

	_ = os.RemoveAll(tmpPath)
	os.Exit(code)
}

func TestNewStartCommand(t *testing.T) {
	t.Run("Should run NewStartCommand and return type correctly", func(t *testing.T) {
		assert.IsType(t, NewStartCommand(config.New()), &Start{})
	})
	t.Run("Should run NewStartCommand and return have expected flags", func(t *testing.T) {
		promptMock := &prompt.Mock{}

		cfg := config.New()
		cfg.WorkDir = &workdir.WorkDir{}

		requirementsMock := &requirements.Mock{}

		analyzerMock := &analyzer.Mock{}
		promptMock.On("Ask").Return("Y", nil)
		analyzerMock.On("Analyze").Return(0, nil)
		requirementsMock.On("ValidateDocker")
		start := &Start{
			useCases:     cli.NewCLIUseCases(),
			configs:      cfg,
			prompt:       promptMock,
			analyzer:     analyzerMock,
			requirements: requirementsMock,
		}
		cmd := start.CreateStartCommand()
		flagSet := cmd.Flags()

		assert.NoError(t, cmd.Execute())
		flags := make([]string, 0)
		flagSet.VisitAll(func(flag *pflag.Flag) {
			if flag.Name == "help" {
				return
			}
			flags = append(flags, "--"+flag.Name)
		})
		expectedFlags := testutil.GetAllStartFlags()
		assert.Equal(t, len(expectedFlags), len(flags))
		for _, flag := range flags {
			assert.Contains(t, expectedFlags, flag)
		}
	})
}

func TestStartCommand_ExecuteUnitTests(t *testing.T) {
	type onFn func(*prompt.Mock, *requirements.Mock, *analyzer.Mock)
	type assertFn func(*testing.T, *prompt.Mock, *requirements.Mock, *analyzer.Mock, *config.Config)

	testcases := []struct {
		name     string
		args     []string
		err      bool
		onFn     onFn
		assertFn assertFn
	}{
		{
			name: "Should execute command exec without error and ask to user if is to run in current directory",
			args: []string{},
			err:  false,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				prompt.On("Ask").Return("Y", nil)
				analyzer.On("Analyze").Return(0, nil)
				requirements.On("ValidateDocker")
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				prompt.AssertCalled(t, "Ask")
				analyzer.AssertCalled(t, "Analyze")
				requirements.AssertCalled(t, "ValidateDocker")
			},
		},
		{
			name: "Should execute command exec without error and not ask if is to run in current directory",
			args: []string{testutil.StartFlagProjectPath, testutil.RootPath},
			err:  false,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				prompt.On("Ask").Return("Y", nil)
				analyzer.On("Analyze").Return(0, nil)
				requirements.On("ValidateDocker")
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.Equal(t, testutil.RootPath, cfg.ProjectPath)

				prompt.AssertNotCalled(t, "Ask")
				analyzer.AssertCalled(t, "Analyze")
				requirements.AssertCalled(t, "ValidateDocker")
			},
		},

		{
			name: "Should execute command exec and return error because found vulnerabilities (-p,-e)",
			args: []string{testutil.StartFlagProjectPath, testutil.RootPath, testutil.StartFlagReturnError},
			err:  true,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				analyzer.On("Analyze").Return(10, nil)
				requirements.On("ValidateDocker")
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.Equal(t, testutil.RootPath, cfg.ProjectPath)
				assert.True(t, cfg.ReturnErrorIfFoundVulnerability)

				prompt.AssertNotCalled(t, "Ask")
				analyzer.AssertCalled(t, "Analyze")
				requirements.AssertCalled(t, "ValidateDocker")
			},
		},
		{
			name: "Should execute command exec and return error because found error when ask but run in current folder",
			args: []string{testutil.StartFlagReturnError},
			err:  true,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				analyzer.On("Analyze").Return(0, nil)
				prompt.On("Ask").Return("", errors.New("some error"))
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.True(t, cfg.ReturnErrorIfFoundVulnerability)

				prompt.AssertCalled(t, "Ask")
				analyzer.AssertNotCalled(t, "Analyze")
				requirements.AssertNotCalled(t, "ValidateDocker")
			},
		},
		{
			name: "Should execute command exec without error and validate if git is installed(--enable-git-history)",
			args: []string{testutil.StartFlagEnableGitHistory, testutil.StartFlagReturnError},
			err:  false,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				prompt.On("Ask").Return("Y", nil)
				analyzer.On("Analyze").Return(0, nil)
				requirements.On("ValidateDocker")
				requirements.On("ValidateGit")

			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.True(t, cfg.ReturnErrorIfFoundVulnerability)
				assert.True(t, cfg.EnableGitHistoryAnalysis)

				prompt.AssertCalled(t, "Ask")
				analyzer.AssertCalled(t, "Analyze")
				requirements.AssertCalled(t, "ValidateDocker")
				requirements.AssertCalled(t, "ValidateGit")
			},
		},
		{
			name: "Should execute command exec without error and not ask because is different project path(-p, -e)",
			args: []string{testutil.StartFlagReturnError, testutil.StartFlagProjectPath, os.TempDir()},
			err:  false,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				prompt.On("Ask").Return("Y", nil)
				analyzer.On("Analyze").Return(0, nil)
				requirements.On("ValidateDocker")
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.True(t, cfg.ReturnErrorIfFoundVulnerability)
				assert.Equal(t, filepath.Clean(os.TempDir()), cfg.ProjectPath)

				prompt.AssertNotCalled(t, "Ask")
				analyzer.AssertCalled(t, "Analyze")
				requirements.AssertCalled(t, "ValidateDocker")
			},
		},
		{
			name: "Should execute command exec and return error because found not accept proceed",
			args: []string{testutil.StartFlagReturnError},
			err:  true,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				analyzer.On("Analyze").Return(0, nil)
				prompt.On("Ask").Return("N", nil)
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.True(t, cfg.ReturnErrorIfFoundVulnerability)

				prompt.AssertCalled(t, "Ask")
				analyzer.AssertNotCalled(t, "Analyze")
				requirements.AssertNotCalled(t, "ValidateDocker")
			},
		},
		{
			name: "Should execute command exec and return error because found invalid RepositoryAuthorization field",
			args: []string{testutil.StartFlagProjectPath, os.TempDir(), testutil.StartFlagAuthorization, "NOT_VALID_AUTHORIZATION", testutil.StartFlagReturnError},
			err:  true,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				prompt.On("Ask").Return("Y", nil)
				analyzer.On("Analyze").Return(10, nil)
				requirements.On("ValidateDocker")
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.Equal(t, filepath.Clean(os.TempDir()), cfg.ProjectPath)
				assert.Equal(t, "NOT_VALID_AUTHORIZATION", cfg.RepositoryAuthorization)
				assert.True(t, cfg.ReturnErrorIfFoundVulnerability)

				prompt.AssertNotCalled(t, "Ask")
				analyzer.AssertNotCalled(t, "Analyze")
				requirements.AssertNotCalled(t, "ValidateDocker")
			},
		},
		{
			name: "Should execute command exec and return success because found valid RepositoryAuthorization field(-a)",
			args: []string{testutil.StartFlagProjectPath, os.TempDir(), testutil.StartFlagAuthorization, "76034e43-bdb8-48d9-a0ad-fc674f0354bb", testutil.StartFlagReturnError},
			err:  false,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				prompt.On("Ask").Return("Y", nil)
				analyzer.On("Analyze").Return(0, nil)
				requirements.On("ValidateDocker")
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.Equal(t, filepath.Clean(os.TempDir()), cfg.ProjectPath)
				assert.Equal(t, "76034e43-bdb8-48d9-a0ad-fc674f0354bb", cfg.RepositoryAuthorization)
				assert.True(t, cfg.ReturnErrorIfFoundVulnerability)

				prompt.AssertNotCalled(t, "Ask")
				analyzer.AssertCalled(t, "Analyze")
				requirements.AssertCalled(t, "ValidateDocker")
			},
		},
		{
			name: "Should execute command exec without error using json output(-o json, -O)",
			args: []string{testutil.StartFlagProjectPath, testutil.RootPath, testutil.StartFlagJSONOutputFilePath, filepath.Join(testutil.RootPath, "cmd", "app", "start", "tmp-json.json"), testutil.StartFlagOutputFormat, "json", testutil.StartFlagReturnError},
			err:  false,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				prompt.On("Ask").Return("Y", nil)
				requirements.On("ValidateDocker")
				analyzer.On("Analyze").Return(0, nil)
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.Equal(t, filepath.Join(testutil.RootPath, "cmd", "app", "start", "tmp-json.json"), cfg.JSONOutputFilePath)
				assert.Equal(t, testutil.RootPath, cfg.ProjectPath)
				assert.Equal(t, "json", cfg.PrintOutputType)

				prompt.AssertNotCalled(t, "Ask")
				requirements.AssertCalled(t, "ValidateDocker")
				analyzer.AssertCalled(t, "Analyze")
			},
		},
		{
			name: "Should execute command exec with error using unknown type output(-o unknown, -O)",
			args: []string{testutil.StartFlagProjectPath, testutil.RootPath, testutil.StartFlagJSONOutputFilePath, filepath.Join(testutil.RootPath, "cmd", "app", "start", "tmp-unknownType.json"), testutil.StartFlagOutputFormat, "unknownTypeOutput", testutil.StartFlagReturnError},
			err:  true,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				analyzer.On("Analyze").Return(0, nil)
				prompt.On("Ask").Return("Y", nil)
				requirements.On("ValidateDocker")
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.Equal(t, testutil.RootPath, cfg.ProjectPath)
				assert.Equal(t, "unknownTypeOutput", cfg.PrintOutputType)
				assert.Equal(t, filepath.Join(testutil.RootPath, "cmd", "app", "start", "tmp-unknownType.json"), cfg.JSONOutputFilePath)

				prompt.AssertNotCalled(t, "Ask")
				analyzer.AssertNotCalled(t, "Analyze")
				requirements.AssertNotCalled(t, "ValidateDocker")
			},
		},
		{
			name: "Should execute command exec without error using sonarqube output (-o sonarqube, -O)",
			args: []string{testutil.StartFlagProjectPath, testutil.RootPath, testutil.StartFlagJSONOutputFilePath, filepath.Join(tmpPath, "tmp-sonarqube.json"), testutil.StartFlagOutputFormat, "sonarqube", testutil.StartFlagReturnError},
			err:  false,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				analyzer.On("Analyze").Return(0, nil)
				prompt.On("Ask").Return("Y", nil)
				requirements.On("ValidateDocker")
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.Equal(t, testutil.RootPath, cfg.ProjectPath)
				assert.Equal(t, "sonarqube", cfg.PrintOutputType)
				assert.Equal(t, filepath.Join(tmpPath, "tmp-sonarqube.json"), cfg.JSONOutputFilePath)

				prompt.AssertNotCalled(t, "Ask")
				analyzer.AssertCalled(t, "Analyze")
				requirements.AssertCalled(t, "ValidateDocker")
			},
		},
		{
			name: "Should execute command exec without error showing info vulnerabilities (--information-severity)",
			args: []string{testutil.StartFlagProjectPath, testutil.RootPath, testutil.StartFlagInformationSeverity},
			err:  false,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				prompt.On("Ask").Return("Y", nil)
				requirements.On("ValidateDocker")
				analyzer.On("Analyze").Return(0, nil)
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.Equal(t, testutil.RootPath, cfg.ProjectPath)
				assert.True(t, cfg.EnableInformationSeverity)

				analyzer.AssertCalled(t, "Analyze")
				requirements.AssertCalled(t, "ValidateDocker")
				prompt.AssertNotCalled(t, "Ask")
			},
		},
		{
			name: "Should execute command exec without error sending to web application (-u,-a)",
			args: []string{testutil.StartFlagProjectPath, testutil.RootPath, testutil.StartFlagHorusecURL, "https://google.com", testutil.StartFlagAuthorization, "76034e43-bdb8-48d9-a0ad-fc674f0354bb"},
			err:  false,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				analyzer.On("Analyze").Return(0, nil)
				prompt.On("Ask").Return("Y", nil)
				requirements.On("ValidateDocker")
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				t.Run("Should execute command exec without error sending to web application (-u,-a)", func(t *testing.T) {
					assert.Equal(t, "https://google.com", cfg.HorusecAPIUri)
					assert.Equal(t, "76034e43-bdb8-48d9-a0ad-fc674f0354bb", cfg.RepositoryAuthorization)

					prompt.AssertNotCalled(t, "Ask")
					analyzer.AssertCalled(t, "Analyze")
					requirements.AssertCalled(t, "ValidateDocker")
				})
			},
		},
		{
			name: "Should execute command exec with error sending to a invalid url web application (-u,-a)",
			args: []string{testutil.StartFlagProjectPath, testutil.RootPath, testutil.StartFlagHorusecURL, "*vsaf&&", testutil.StartFlagAuthorization, "76034e43-bdb8-48d9-a0ad-fc674f0354bb"},
			err:  true,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				analyzer.On("Analyze").Return(0, nil)
				prompt.On("Ask").Return("Y", nil)
				requirements.On("ValidateDocker")
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.Equal(t, "*vsaf&&", cfg.HorusecAPIUri)
				assert.Equal(t, "76034e43-bdb8-48d9-a0ad-fc674f0354bb", cfg.RepositoryAuthorization)

				prompt.AssertNotCalled(t, "Ask")
				analyzer.AssertNotCalled(t, "Analyze")
				requirements.AssertNotCalled(t, "ValidateDocker")
			},
		},
		{
			name: "Should execute command exec without error and return vulnerabilities but ignore vulnerabilities of type HIGH (-s)",
			args: []string{testutil.StartFlagProjectPath, testutil.RootPath, testutil.StartFlagIgnoreSeverity, "CRITICAL, LOW"},
			err:  false,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {

				analyzer.On("Analyze").Return(0, nil)
				prompt.On("Ask").Return("Y", nil)
				requirements.On("ValidateDocker")
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.Equal(t, testutil.RootPath, cfg.ProjectPath)
				assert.Equal(t, []string{"CRITICAL", "LOW"}, cfg.SeveritiesToIgnore)

				prompt.AssertNotCalled(t, "Ask")
				analyzer.AssertCalled(t, "Analyze")
				requirements.AssertCalled(t, "ValidateDocker")
			},
		},
		{
			name: "Should execute command exec with error and not return vulnerabilities when set to ignore unknown type of vulnerability (-s)",
			args: []string{testutil.StartFlagProjectPath, testutil.RootPath, testutil.StartFlagIgnoreSeverity, "potato, shoes"},
			err:  true,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				analyzer.On("Analyze").Return(0, nil)
				prompt.On("Ask").Return("Y", nil)
				requirements.On("ValidateDocker")
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.Equal(t, testutil.RootPath, cfg.ProjectPath)
				assert.Equal(t, []string{"potato", " shoes"}, cfg.SeveritiesToIgnore)

				prompt.AssertNotCalled(t, "Ask")
				analyzer.AssertNotCalled(t, "Analyze")
				requirements.AssertNotCalled(t, "ValidateDocker")
			},
		},
		{
			name: "Should execute command exec without error and not return vulnerabilities when set valid certificate path (-C --certificate-path)",
			args: []string{testutil.StartFlagProjectPath, testutil.RootPath, testutil.StartFlagCertificatePath, filepath.Join(testutil.RootPath, "..")},
			err:  false,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				analyzer.On("Analyze").Return(0, nil)
				prompt.On("Ask").Return("Y", nil)
				requirements.On("ValidateDocker")
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.Equal(t, testutil.RootPath, cfg.ProjectPath)
				assert.Equal(t, filepath.Join(testutil.RootPath, ".."), cfg.CertPath)

				prompt.AssertNotCalled(t, "Ask")
				analyzer.AssertCalled(t, "Analyze")
				requirements.AssertCalled(t, "ValidateDocker")
			},
		},
		{
			name: "Should execute command exec with error and not return vulnerabilities when set invalid certificate path (-C --certificate-path)",
			args: []string{testutil.StartFlagProjectPath, testutil.RootPath, testutil.StartFlagCertificatePath, "invalidPath"},
			err:  true,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				analyzer.On("Analyze").Return(0, nil)
				prompt.On("Ask").Return("Y", nil)
				requirements.On("ValidateDocker")
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.Equal(t, testutil.RootPath, cfg.ProjectPath)
				assert.Equal(t, "invalidPath", cfg.CertPath)

				prompt.AssertNotCalled(t, "Ask")
				analyzer.AssertNotCalled(t, "Analyze")
				requirements.AssertNotCalled(t, "ValidateDocker")
			},
		},
		{
			name: "Should execute command exec without error and not return vulnerabilities when set valid analysis timeout (-t --analysis-timeout)\"",
			args: []string{testutil.StartFlagProjectPath, testutil.RootPath, testutil.StartFlagAnalysisTimeout, "123"},
			err:  false,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				analyzer.On("Analyze").Return(0, nil)
				prompt.On("Ask").Return("Y", nil)
				requirements.On("ValidateDocker")
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.Equal(t, testutil.RootPath, cfg.ProjectPath)
				assert.Equal(t, int64(123), cfg.TimeoutInSecondsAnalysis)

				prompt.AssertNotCalled(t, "Ask")
				analyzer.AssertCalled(t, "Analyze")
				requirements.AssertCalled(t, "ValidateDocker")
			},
		},
		{
			name: "Should execute command exec with error and not return vulnerabilities when set invalid analysis timeout (-t --analysis-timeout)",
			args: []string{testutil.StartFlagProjectPath, testutil.RootPath, testutil.StartFlagAnalysisTimeout, "potato"},
			err:  true,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				analyzer.On("Analyze").Return(0, nil)
				prompt.On("Ask").Return("Y", nil)
				requirements.On("ValidateDocker")
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.NotEqual(t, "potato", cfg.TimeoutInSecondsAnalysis)

				prompt.AssertNotCalled(t, "Ask")
				analyzer.AssertNotCalled(t, "Analyze")
				requirements.AssertNotCalled(t, "ValidateDocker")
			},
		},
		{
			name: "Should execute command exec without error and not return vulnerabilities when set disable docker (-D --disable-docker)",
			args: []string{testutil.StartFlagDisableDocker},
			err:  false,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				analyzer.On("Analyze").Return(0, nil)
				prompt.On("Ask").Return("Y", nil)
				requirements.On("ValidateDocker")
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.True(t, cfg.DisableDocker)

				prompt.AssertCalled(t, "Ask")
				analyzer.AssertCalled(t, "Analyze")
				requirements.AssertNotCalled(t, "ValidateDocker")
			},
		},
		{
			name: "Should execute command exec without error and not return vulnerabilities when set valid request timeout (-r --request-timeout)",
			args: []string{testutil.StartFlagRequestTimeout, "123"},
			err:  false,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				analyzer.On("Analyze").Return(0, nil)
				prompt.On("Ask").Return("Y", nil)
				requirements.On("ValidateDocker")
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.Equal(t, int64(123), cfg.TimeoutInSecondsRequest)

				prompt.AssertCalled(t, "Ask")
				analyzer.AssertCalled(t, "Analyze")
				requirements.AssertCalled(t, "ValidateDocker")
			},
		},
		{
			name: "Should execute command exec with error and not return vulnerabilities when set invalid request timeout (-r --request-timeout)",
			args: []string{testutil.StartFlagRequestTimeout, "potato"},
			err:  true,
			onFn: func(prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock) {
				analyzer.On("Analyze").Return(0, nil)
				prompt.On("Ask").Return("Y", nil)
				requirements.On("ValidateDocker")
			},
			assertFn: func(t *testing.T, prompt *prompt.Mock, requirements *requirements.Mock, analyzer *analyzer.Mock, cfg *config.Config) {
				assert.NotEqual(t, "potato", cfg.TimeoutInSecondsRequest)

				prompt.AssertNotCalled(t, "Ask")
				analyzer.AssertNotCalled(t, "Analyze")
				requirements.AssertNotCalled(t, "ValidateDocker")
			},
		},
	}
	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			promptMock, cfg, requirementsMock, analyzerMock, start := getMocksAndStartStruct()
			tt.onFn(promptMock, requirementsMock, analyzerMock)

			cmd := start.CreateStartCommand()

			cmd.SetArgs(tt.args)
			if tt.err {
				assert.Error(t, cmd.Execute())
			} else {
				assert.NoError(t, cmd.Execute())
			}

			tt.assertFn(t, promptMock, requirementsMock, analyzerMock, cfg)
		})
	}
}
func TestStartCommand_ExecuteIntegrationTest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	t.Run("Should execute command exec without error using json output", func(t *testing.T) {
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		cfg := config.New()
		cfg.WorkDir = &workdir.WorkDir{}

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			useCases:     cli.NewCLIUseCases(),
			configs:      cfg,
			prompt:       promptMock,
			analyzer:     nil,
			requirements: requirementsMock,
		}

		oldStdout := os.Stdout

		r, w, _ := os.Pipe()
		os.Stdout = w
		outC := make(chan string)
		go func() {
			var buf bytes.Buffer
			_, _ = io.Copy(&buf, r)
			outC <- buf.String()
		}()
		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(w)
		outputPathJSON := filepath.Join(tmpPath, "tmp-json.json")
		cobraCmd.SetArgs([]string{
			testutil.StartFlagProjectPath, ".",
			testutil.StartFlagOutputFormat, "json",
			testutil.StartFlagJSONOutputFilePath, outputPathJSON})

		assert.NoError(t, cobraCmd.Execute())
		err := w.Close()
		assert.NoError(t, err)
		os.Stdout = oldStdout
		output := <-outC

		assert.NotEmpty(t, output)
		assert.Contains(t, output, "{HORUSEC_CLI} PLEASE DON'T REMOVE ")
		assert.Contains(t, output, "FOLDER BEFORE THE ANALYSIS FINISH! Don’t worry, we’ll remove it after the analysis ends automatically! Project sent to folder in location: ")
		assert.Contains(t, output, "Horusec will return a timeout after 600 seconds. This time can be customized in the cli settings.")
		assert.Contains(t, output, "{HORUSEC_CLI} Writing output JSON to file in the path:")
		assert.Contains(t, output, outputPathJSON)
		assert.Contains(t, output, "{HORUSEC_CLI} No authorization token was found, your code it is not going to be sent to horusec. Please enter a token with the -a flag to configure and save your analysis")
		assert.Contains(t, output, "YOUR ANALYSIS HAD FINISHED WITHOUT ANY VULNERABILITY!")
		assert.Contains(t, output, "{HORUSEC_CLI} Horusec not show info vulnerabilities in this analysis")

		bytesFile, err := os.ReadFile(outputPathJSON)
		assert.NoError(t, err)
		bytesFileString := string(bytesFile)
		assert.Contains(t, bytesFileString, "\"analysisVulnerabilities\": null")
		promptMock.AssertNotCalled(t, "Ask")
		assert.NoError(t, os.RemoveAll(outputPathJSON))
	})
	t.Run("Should execute command exec without error showing info vulnerabilities", func(t *testing.T) {
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		cfg := config.New()
		cfg.WorkDir = &workdir.WorkDir{}

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			useCases:     cli.NewCLIUseCases(),
			configs:      cfg,
			prompt:       promptMock,
			analyzer:     nil,
			requirements: requirementsMock,
		}
		oldStdout := os.Stdout

		r, w, _ := os.Pipe()
		os.Stdout = w
		outC := make(chan string)
		go func() {
			var buf bytes.Buffer
			_, _ = io.Copy(&buf, r)
			outC <- buf.String()
		}()
		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(w)
		cobraCmd.SetArgs([]string{"-p", "./", "--information-severity", "true"})

		assert.NoError(t, cobraCmd.Execute())
		err := w.Close()
		os.Stdout = oldStdout
		output := <-outC

		assert.NoError(t, err)
		assert.NotEmpty(t, output)
		assert.Contains(t, output, "{HORUSEC_CLI} PLEASE DON'T REMOVE ")
		assert.Contains(t, output, "FOLDER BEFORE THE ANALYSIS FINISH! Don’t worry, we’ll remove it after the analysis ends automatically! Project sent to folder in location: ")
		assert.Contains(t, output, "Horusec will return a timeout after 600 seconds. This time can be customized in the cli settings.")
		assert.Contains(t, output, "{HORUSEC_CLI} No authorization token was found, your code it is not going to be sent to horusec. Please enter a token with the -a flag to configure and save your analysis")
		assert.Contains(t, output, "YOUR ANALYSIS HAD FINISHED WITHOUT ANY VULNERABILITY!")
		assert.NotContains(t, output, "{HORUSEC_CLI} Horusec not show info vulnerabilities in this analysis")

		promptMock.AssertNotCalled(t, "Ask")
	})
	t.Run("Should execute command exec without error sending to web application", func(t *testing.T) {
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		cfg := config.New()
		cfg.WorkDir = &workdir.WorkDir{}

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			useCases:     cli.NewCLIUseCases(),
			configs:      cfg,
			prompt:       promptMock,
			analyzer:     nil,
			requirements: requirementsMock,
		}
		oldStdout := os.Stdout

		r, w, _ := os.Pipe()
		os.Stdout = w
		outC := make(chan string)
		go func() {
			var buf bytes.Buffer
			_, _ = io.Copy(&buf, r)
			outC <- buf.String()
		}()
		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(w)
		cobraCmd.SetArgs([]string{"-p", "./", "-u", "https://google.com", "-a", uuid.NewString()})

		assert.NoError(t, cobraCmd.Execute())
		err := w.Close()
		os.Stdout = oldStdout
		output := <-outC

		assert.NoError(t, err)
		assert.NotEmpty(t, output)
		assert.Contains(t, output, "{HORUSEC_CLI} PLEASE DON'T REMOVE ")
		assert.Contains(t, output, "FOLDER BEFORE THE ANALYSIS FINISH! Don’t worry, we’ll remove it after the analysis ends automatically! Project sent to folder in location: ")
		assert.Contains(t, output, "Horusec will return a timeout after 600 seconds. This time can be customized in the cli settings.")
		assert.NotContains(t, output, "{HORUSEC_CLI} No authorization token was found, your code it is not going to be sent to horusec. Please enter a token with the -a flag to configure and save your analysis")
		assert.Contains(t, output, "YOUR ANALYSIS HAD FINISHED WITHOUT ANY VULNERABILITY!")

		promptMock.AssertNotCalled(t, "Ask")
	})
	t.Run("Should execute command exec without error using sonarqube output", func(t *testing.T) {
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		cfg := config.New()
		cfg.WorkDir = &workdir.WorkDir{}

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			useCases:     cli.NewCLIUseCases(),
			configs:      cfg,
			prompt:       promptMock,
			analyzer:     nil,
			requirements: requirementsMock,
		}

		oldStdout := os.Stdout

		r, w, _ := os.Pipe()
		os.Stdout = w
		outC := make(chan string)
		go func() {
			var buf bytes.Buffer
			_, _ = io.Copy(&buf, r)
			outC <- buf.String()
		}()
		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(w)
		cobraCmd.SetArgs([]string{"-p", "./", "-o", "sonarqube", "-O", "./tmp-sonarqube.json"})

		assert.NoError(t, cobraCmd.Execute())
		err := w.Close()
		os.Stdout = oldStdout
		output := <-outC

		assert.NoError(t, err)
		assert.NotEmpty(t, output)
		assert.Contains(t, output, "{HORUSEC_CLI} PLEASE DON'T REMOVE ")
		assert.Contains(t, output, "FOLDER BEFORE THE ANALYSIS FINISH! Don’t worry, we’ll remove it after the analysis ends automatically! Project sent to folder in location: ")
		assert.Contains(t, output, "Horusec will return a timeout after 600 seconds. This time can be customized in the cli settings.")
		assert.Contains(t, output, "{HORUSEC_CLI} Writing output JSON to file in the path:")
		assert.Contains(t, output, "cmd/app/start/tmp-sonarqube.json")
		assert.Contains(t, output, "{HORUSEC_CLI} No authorization token was found, your code it is not going to be sent to horusec. Please enter a token with the -a flag to configure and save your analysis")
		assert.Contains(t, output, "YOUR ANALYSIS HAD FINISHED WITHOUT ANY VULNERABILITY!")
		assert.Contains(t, output, "{HORUSEC_CLI} Horusec not show info vulnerabilities in this analysis")

		bytesFile, err := os.ReadFile("./tmp-sonarqube.json")
		assert.NoError(t, err)
		bytesFileString := string(bytesFile)
		assert.Contains(t, bytesFileString, "\"issues\": []")
		promptMock.AssertNotCalled(t, "Ask")
		assert.NoError(t, os.RemoveAll("./tmp-sonarqube.json"))
	})
	t.Run("Should execute command exec without error and return vulnerabilities of gitleaks but ignore vulnerabilities of the HIGH", func(t *testing.T) {
		srcProject := testutil.LeaksExample1
		dstProject := filepath.Join(tmpPath, uuid.NewString())
		assert.NoError(t, copy.Copy(srcProject, dstProject, func(src string) bool {
			return false
		}))
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		cfg := config.New()
		cfg.ConfigFilePath = "./not-exists.json"
		cfg.WorkDir = &workdir.WorkDir{}

		requirementsMock := &requirements.Mock{}
		requirementsMock.On("ValidateDocker")

		cmd := &Start{
			useCases:     cli.NewCLIUseCases(),
			configs:      cfg,
			prompt:       promptMock,
			analyzer:     nil,
			requirements: requirementsMock,
		}

		oldStdout := os.Stdout

		r, w, _ := os.Pipe()
		os.Stdout = w
		outC := make(chan string)
		go func() {
			var buf bytes.Buffer
			_, _ = io.Copy(&buf, r)
			outC <- buf.String()
		}()
		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(w)
		cobraCmd.SetArgs([]string{"-p", dstProject, "-s", "CRITICAL, LOW"})

		assert.NoError(t, cobraCmd.Execute())
		err := w.Close()
		os.Stdout = oldStdout
		output := <-outC

		assert.NoError(t, err)
		assert.NotEmpty(t, output)
		assert.Contains(t, output, "{HORUSEC_CLI} PLEASE DON'T REMOVE ")
		assert.Contains(t, output, "FOLDER BEFORE THE ANALYSIS FINISH! Don’t worry, we’ll remove it after the analysis ends automatically! Project sent to folder in location: ")
		assert.Contains(t, output, "Horusec will return a timeout after 600 seconds. This time can be customized in the cli settings.")
		assert.Contains(t, output, "Total of Vulnerability MEDIUM is: 5")
		assert.Contains(t, output, "Total of Vulnerability HIGH is: 11")
		assert.Contains(t, output, "{HORUSEC_CLI} No authorization token was found, your code it is not going to be sent to horusec. Please enter a token with the -a flag to configure and save your analysis")
		assert.Contains(t, output, "{HORUSEC_CLI} 16 VULNERABILITIES WERE FOUND IN YOUR CODE SENT TO HORUSEC, TO SEE MORE DETAILS USE THE LOG LEVEL AS DEBUG AND TRY AGAIN")
		assert.Contains(t, output, "{HORUSEC_CLI} Horusec not show info vulnerabilities in this analysis")
		promptMock.AssertNotCalled(t, "Ask")
		assert.NoError(t, os.RemoveAll(dstProject))
	})
	t.Run("Should execute command exec without error and return vulnerabilities of gitleaks and return error", func(t *testing.T) {
		srcProject := testutil.LeaksExample1
		dstProject := filepath.Join(tmpPath, uuid.NewString())
		assert.NoError(t, copy.Copy(srcProject, dstProject, func(src string) bool {
			return false
		}))
		promptMock := &prompt.Mock{}
		promptMock.On("Ask").Return("Y", nil)

		cfg := config.New()
		cfg.WorkDir = &workdir.WorkDir{}

		requirementMock := &requirements.Mock{}
		requirementMock.On("ValidateDocker")

		cmd := &Start{
			useCases:     cli.NewCLIUseCases(),
			configs:      cfg,
			prompt:       promptMock,
			analyzer:     nil,
			requirements: requirementMock,
		}
		oldStdout := os.Stdout

		r, w, _ := os.Pipe()
		os.Stdout = w
		outC := make(chan string)
		go func() {
			var buf bytes.Buffer
			_, _ = io.Copy(&buf, r)
			outC <- buf.String()
		}()
		cobraCmd := cmd.CreateStartCommand()
		cobraCmd.SetOut(w)
		cobraCmd.SetArgs([]string{"-p", dstProject})

		assert.NoError(t, cobraCmd.Execute())
		err := w.Close()
		os.Stdout = oldStdout
		output := <-outC
		assert.NoError(t, err)
		assert.NotEmpty(t, output)

		assert.Contains(t, output, "{HORUSEC_CLI} PLEASE DON'T REMOVE ")
		assert.Contains(t, output, "FOLDER BEFORE THE ANALYSIS FINISH! Don’t worry, we’ll remove it after the analysis ends automatically! Project sent to folder in location: ")
		assert.Contains(t, output, "Horusec will return a timeout after 600 seconds. This time can be customized in the cli settings.")
		assert.Contains(t, output, "{HORUSEC_CLI} No authorization token was found, your code it is not going to be sent to horusec. Please enter a token with the -a flag to configure and save your analysis")
		assert.Contains(t, output, "{HORUSEC_CLI} 25 VULNERABILITIES WERE FOUND IN YOUR CODE SENT TO HORUSEC, TO SEE MORE DETAILS USE THE LOG LEVEL AS DEBUG AND TRY AGAIN")
		assert.Contains(t, output, "{HORUSEC_CLI} Horusec not show info vulnerabilities in this analysis")
		assert.Contains(t, output, "")
		promptMock.AssertNotCalled(t, "Ask")
		assert.NoError(t, os.RemoveAll(dstProject))
	})
}
func getMocksAndStartStruct() (*prompt.Mock, *config.Config, *requirements.Mock, *analyzer.Mock, *Start) {
	promptMock := &prompt.Mock{}

	cfg := config.New()
	cfg.WorkDir = &workdir.WorkDir{}

	requirementsMock := &requirements.Mock{}

	analyzerMock := &analyzer.Mock{}

	start := &Start{
		useCases:     cli.NewCLIUseCases(),
		configs:      cfg,
		prompt:       promptMock,
		analyzer:     analyzerMock,
		requirements: requirementsMock,
	}
	return promptMock, cfg, requirementsMock, analyzerMock, start
}
