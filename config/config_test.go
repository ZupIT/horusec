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

package config_test

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/enums/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec/cmd/app/start"
	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/entities/workdir"
)

func TestMain(m *testing.M) {
	_ = os.RemoveAll("./tmp")
	_ = os.MkdirAll("./tmp", 0o750)
	code := m.Run()
	_ = os.RemoveAll("./tmp")
	os.Exit(code)
}

func TestNewHorusecConfig(t *testing.T) {
	t.Run("Should return horusec config with your default values", func(t *testing.T) {
		currentPath, _ := os.Getwd()
		configs := config.New()
		assert.Equal(t, "{{VERSION_NOT_FOUND}}", configs.Version)
		assert.Equal(t, "http://0.0.0.0:8000", configs.HorusecAPIUri)
		assert.Equal(t, int64(300), configs.TimeoutInSecondsRequest)
		assert.Equal(t, int64(600), configs.TimeoutInSecondsAnalysis)
		assert.Equal(t, int64(15), configs.MonitorRetryInSeconds)
		assert.Equal(t, uuid.Nil.String(), configs.RepositoryAuthorization)
		assert.Equal(t, "", configs.PrintOutputType)
		assert.Equal(t, "", configs.JSONOutputFilePath)
		assert.Equal(t, 1, len(configs.SeveritiesToIgnore))
		assert.Equal(t, 2, len(configs.FilesOrPathsToIgnore))
		assert.Equal(t, false, configs.ReturnErrorIfFoundVulnerability)
		assert.Equal(t, currentPath, configs.ProjectPath)
		assert.Equal(t, workdir.Default(), configs.WorkDir)
		assert.Equal(t, false, configs.EnableGitHistoryAnalysis)
		assert.Equal(t, false, configs.CertInsecureSkipVerify)
		assert.Equal(t, "", configs.CertPath)
		assert.Equal(t, false, configs.EnableCommitAuthor)
		assert.Equal(t, "config", configs.RepositoryName)
		assert.Equal(t, 0, len(configs.RiskAcceptHashes))
		assert.Equal(t, 0, len(configs.FalsePositiveHashes))
		assert.Equal(t, 0, len(configs.Headers))
		assert.Equal(t, "", configs.ContainerBindProjectPath)
		assert.Equal(t, true, configs.IsEmptyRepositoryAuthorization())
		assert.Equal(t, 22, len(configs.ToolsConfig))
		assert.Equal(t, false, configs.DisableDocker)
		assert.Equal(t, "", configs.CustomRulesPath)
		assert.Equal(t, false, configs.EnableInformationSeverity)
		assert.Equal(t, 12, len(configs.CustomImages))
		assert.Equal(t, 1, len(configs.ShowVulnerabilitiesTypes))
		assert.Equal(t, false, configs.EnableOwaspDependencyCheck)
		assert.Equal(t, false, configs.EnableShellCheck)
		assert.Equal(t, false, configs.EnableSemanticEngine)
	})
	t.Run("Should return horusec config using new config file", func(t *testing.T) {
		viper.Reset()
		currentPath, err := os.Getwd()
		configFilePath := path.Join(currentPath, ".example-horusec-cli.json")
		assert.NoError(t, err)
		configs := config.New()
		configs.ConfigFilePath = configFilePath
		configs.LoadFromConfigFile()
		assert.Equal(t, configFilePath, configs.ConfigFilePath)
		assert.Equal(t, "http://new-viper.horusec.com", configs.HorusecAPIUri)
		assert.Equal(t, int64(20), configs.TimeoutInSecondsRequest)
		assert.Equal(t, int64(100), configs.TimeoutInSecondsAnalysis)
		assert.Equal(t, int64(10), configs.MonitorRetryInSeconds)
		assert.Equal(t, "8beffdca-636e-4d73-a22f-b0f7c3cff1c4", configs.RepositoryAuthorization)
		assert.Equal(t, "json", configs.PrintOutputType)
		assert.Equal(t, "./output.json", configs.JSONOutputFilePath)
		assert.Equal(t, []string{"INFO"}, configs.SeveritiesToIgnore)
		assert.Equal(t, []string{"./assets"}, configs.FilesOrPathsToIgnore)
		assert.Equal(t, true, configs.ReturnErrorIfFoundVulnerability)
		assert.Equal(t, "./", configs.ProjectPath)
		assert.Equal(t, workdir.Default(), configs.WorkDir)
		assert.Equal(t, true, configs.EnableGitHistoryAnalysis)
		assert.Equal(t, true, configs.CertInsecureSkipVerify)
		assert.Equal(t, "", configs.CertPath)
		assert.Equal(t, true, configs.EnableCommitAuthor)
		assert.Equal(t, "horus", configs.RepositoryName)
		assert.Equal(t, []string{"hash3", "hash4"}, configs.RiskAcceptHashes)
		assert.Equal(t, []string{"hash1", "hash2"}, configs.FalsePositiveHashes)
		assert.Equal(t, map[string]string{"x-headers": "some-other-value"}, configs.Headers)
		assert.Equal(t, "test", configs.ContainerBindProjectPath)
		assert.Equal(t, true, configs.DisableDocker)
		assert.Equal(t, "test", configs.CustomRulesPath)
		assert.Equal(t, true, configs.EnableInformationSeverity)
		assert.Equal(t, true, configs.EnableOwaspDependencyCheck)
		assert.Equal(t, true, configs.EnableShellCheck)
		assert.Equal(t, []string{vulnerability.Vulnerability.ToString(), vulnerability.FalsePositive.ToString()}, configs.ShowVulnerabilitiesTypes)
		assert.Equal(t, toolsconfig.Config{
			IsToIgnore: true,
		}, configs.ToolsConfig[tools.GoSec])
		assert.Equal(t, "docker.io/company/go:latest", configs.CustomImages[languages.Go])
		assert.Equal(t, true, configs.EnableSemanticEngine)
	})
	t.Run("Should return horusec config using config file and override by environment", func(t *testing.T) {
		viper.Reset()
		authorization := uuid.New().String()
		currentPath, err := os.Getwd()
		configFilePath := path.Join(currentPath + "/.example-horusec-cli.json")
		assert.NoError(t, err)
		configs := config.New()
		configs.ConfigFilePath = configFilePath
		configs.LoadFromConfigFile()
		assert.Equal(t, configFilePath, configs.ConfigFilePath)
		assert.Equal(t, "http://new-viper.horusec.com", configs.HorusecAPIUri)
		assert.Equal(t, int64(20), configs.TimeoutInSecondsRequest)
		assert.Equal(t, int64(100), configs.TimeoutInSecondsAnalysis)
		assert.Equal(t, int64(10), configs.MonitorRetryInSeconds)
		assert.Equal(t, "8beffdca-636e-4d73-a22f-b0f7c3cff1c4", configs.RepositoryAuthorization)
		assert.Equal(t, "json", configs.PrintOutputType)
		assert.Equal(t, "./output.json", configs.JSONOutputFilePath)
		assert.Equal(t, []string{"INFO"}, configs.SeveritiesToIgnore)
		assert.Equal(t, []string{"./assets"}, configs.FilesOrPathsToIgnore)
		assert.Equal(t, true, configs.ReturnErrorIfFoundVulnerability)
		assert.Equal(t, "./", configs.ProjectPath)
		assert.Equal(t, workdir.Default(), configs.WorkDir)
		assert.Equal(t, true, configs.EnableGitHistoryAnalysis)
		assert.Equal(t, true, configs.CertInsecureSkipVerify)
		assert.Equal(t, "", configs.CertPath)
		assert.Equal(t, true, configs.EnableCommitAuthor)
		assert.Equal(t, "horus", configs.RepositoryName)
		assert.Equal(t, []string{"hash3", "hash4"}, configs.RiskAcceptHashes)
		assert.Equal(t, []string{"hash1", "hash2"}, configs.FalsePositiveHashes)
		assert.Equal(t, []string{vulnerability.Vulnerability.ToString(), vulnerability.FalsePositive.ToString()}, configs.ShowVulnerabilitiesTypes)
		assert.Equal(t, map[string]string{"x-headers": "some-other-value"}, configs.Headers)
		assert.Equal(t, "test", configs.ContainerBindProjectPath)
		assert.Equal(t, true, configs.EnableInformationSeverity)
		assert.Equal(t, true, configs.EnableOwaspDependencyCheck)
		assert.Equal(t, true, configs.EnableShellCheck)
		assert.Equal(t, toolsconfig.Config{
			IsToIgnore: true,
		}, configs.ToolsConfig[tools.GoSec])
		assert.Equal(t, "docker.io/company/go:latest", configs.CustomImages[languages.Go])
		assert.Equal(t, true, configs.EnableSemanticEngine)

		assert.NoError(t, os.Setenv(config.EnvHorusecAPIUri, "http://horusec.com"))
		assert.NoError(t, os.Setenv(config.EnvTimeoutInSecondsRequest, "99"))
		assert.NoError(t, os.Setenv(config.EnvTimeoutInSecondsAnalysis, "999"))
		assert.NoError(t, os.Setenv(config.EnvMonitorRetryInSeconds, "20"))
		assert.NoError(t, os.Setenv(config.EnvRepositoryAuthorization, authorization))
		assert.NoError(t, os.Setenv(config.EnvPrintOutputType, "sonarqube"))
		assert.NoError(t, os.Setenv(config.EnvJSONOutputFilePath, filepath.Join(os.TempDir(), "output-sonarqube.json")))
		assert.NoError(t, os.Setenv(config.EnvSeveritiesToIgnore, "INFO"))
		assert.NoError(t, os.Setenv(config.EnvFilesOrPathsToIgnore, "**/*_test.go, **/*_mock.go"))
		assert.NoError(t, os.Setenv(config.EnvReturnErrorIfFoundVulnerability, "false"))
		assert.NoError(t, os.Setenv(config.EnvProjectPath, "./horusec-manager"))
		assert.NoError(t, os.Setenv(config.EnvEnableGitHistoryAnalysis, "false"))
		assert.NoError(t, os.Setenv(config.EnvCertInsecureSkipVerify, "false"))
		assert.NoError(t, os.Setenv(config.EnvCertPath, "./"))
		assert.NoError(t, os.Setenv(config.EnvEnableCommitAuthor, "false"))
		assert.NoError(t, os.Setenv(config.EnvRepositoryName, "my-project"))
		assert.NoError(t, os.Setenv(config.EnvFalsePositiveHashes, "hash9, hash8"))
		assert.NoError(t, os.Setenv(config.EnvRiskAcceptHashes, "hash7, hash6"))
		assert.NoError(t, os.Setenv(config.EnvHeaders, "{\"x-auth\": \"987654321\"}"))
		assert.NoError(t, os.Setenv(config.EnvContainerBindProjectPath, "./my-path"))
		assert.NoError(t, os.Setenv(config.EnvDisableDocker, "true"))
		assert.NoError(t, os.Setenv(config.EnvEnableOwaspDependencyCheck, "true"))
		assert.NoError(t, os.Setenv(config.EnvEnableShellCheck, "true"))
		assert.NoError(t, os.Setenv(config.EnvCustomRulesPath, "test"))
		assert.NoError(t, os.Setenv(config.EnvEnableInformationSeverity, "true"))
		assert.NoError(t, os.Setenv(config.EnvEnableSemanticEngine, "false"))
		assert.NoError(t, os.Setenv(
			config.EnvLogFilePath, filepath.Join(os.TempDir(), "test.log")),
		)
		configs.LoadFromEnvironmentVariables()

		assert.Equal(t, configFilePath, configs.ConfigFilePath)
		assert.Equal(t, "http://horusec.com", configs.HorusecAPIUri)
		assert.Equal(t, int64(99), configs.TimeoutInSecondsRequest)
		assert.Equal(t, int64(999), configs.TimeoutInSecondsAnalysis)
		assert.Equal(t, int64(20), configs.MonitorRetryInSeconds)
		assert.Equal(t, authorization, configs.RepositoryAuthorization)
		assert.Equal(t, "sonarqube", configs.PrintOutputType)
		assert.Equal(t, filepath.Join(os.TempDir(), "output-sonarqube.json"), configs.JSONOutputFilePath)
		assert.Equal(t, []string{"INFO"}, configs.SeveritiesToIgnore)
		assert.Equal(t, []string{"**/*_test.go", "**/*_mock.go"}, configs.FilesOrPathsToIgnore)
		assert.Equal(t, false, configs.ReturnErrorIfFoundVulnerability)
		assert.Equal(t, "./horusec-manager", configs.ProjectPath)
		assert.Equal(t, workdir.Default(), configs.WorkDir)
		assert.Equal(t, false, configs.EnableGitHistoryAnalysis)
		assert.Equal(t, false, configs.CertInsecureSkipVerify)
		assert.Equal(t, "./", configs.CertPath)
		assert.Equal(t, false, configs.EnableCommitAuthor)
		assert.Equal(t, "my-project", configs.RepositoryName)
		assert.Equal(t, []string{"hash7", "hash6"}, configs.RiskAcceptHashes)
		assert.Equal(t, []string{"hash9", "hash8"}, configs.FalsePositiveHashes)
		assert.Equal(t, map[string]string{"x-auth": "987654321"}, configs.Headers)
		assert.Equal(t, "./my-path", configs.ContainerBindProjectPath)
		assert.Equal(t, true, configs.DisableDocker)
		assert.Equal(t, "test", configs.CustomRulesPath)
		assert.Equal(t, true, configs.EnableInformationSeverity)
		assert.Equal(t, true, configs.EnableOwaspDependencyCheck)
		assert.Equal(t, true, configs.EnableShellCheck)
		assert.Equal(t, false, configs.EnableSemanticEngine)
		assert.Equal(
			t,
			[]string{vulnerability.Vulnerability.ToString(), vulnerability.FalsePositive.ToString()},
			configs.ShowVulnerabilitiesTypes,
		)
	})
	t.Run("Should return horusec config using config file and override by environment and override by flags", func(t *testing.T) {
		viper.Reset()
		authorization := uuid.New().String()
		currentPath, err := os.Getwd()
		configFilePath := path.Join(currentPath, ".example-horusec-cli.json")
		assert.NoError(t, err)
		configs := config.New()
		configs.ConfigFilePath = configFilePath
		configs.LoadFromConfigFile()
		assert.Equal(t, configFilePath, configs.ConfigFilePath)
		assert.Equal(t, "http://new-viper.horusec.com", configs.HorusecAPIUri)
		assert.Equal(t, int64(20), configs.TimeoutInSecondsRequest)
		assert.Equal(t, int64(100), configs.TimeoutInSecondsAnalysis)
		assert.Equal(t, int64(10), configs.MonitorRetryInSeconds)
		assert.Equal(t, "8beffdca-636e-4d73-a22f-b0f7c3cff1c4", configs.RepositoryAuthorization)
		assert.Equal(t, "json", configs.PrintOutputType)
		assert.Equal(t, "./output.json", configs.JSONOutputFilePath)
		assert.Equal(t, []string{"INFO"}, configs.SeveritiesToIgnore)
		assert.Equal(t, []string{"./assets"}, configs.FilesOrPathsToIgnore)
		assert.Equal(t, true, configs.ReturnErrorIfFoundVulnerability)
		assert.Equal(t, "./", configs.ProjectPath)
		assert.Equal(t, workdir.Default(), configs.WorkDir)
		assert.Equal(t, true, configs.EnableGitHistoryAnalysis)
		assert.Equal(t, true, configs.CertInsecureSkipVerify)
		assert.Equal(t, "", configs.CertPath)
		assert.Equal(t, true, configs.EnableCommitAuthor)
		assert.Equal(t, "horus", configs.RepositoryName)
		assert.Equal(t, []string{"hash3", "hash4"}, configs.RiskAcceptHashes)
		assert.Equal(t, []string{"hash1", "hash2"}, configs.FalsePositiveHashes)
		assert.Equal(t, []string{vulnerability.Vulnerability.ToString(), vulnerability.FalsePositive.ToString()}, configs.ShowVulnerabilitiesTypes)
		assert.Equal(t, map[string]string{"x-headers": "some-other-value"}, configs.Headers)
		assert.Equal(t, "test", configs.ContainerBindProjectPath)
		assert.Equal(t, true, configs.EnableInformationSeverity)
		assert.Equal(t, true, configs.EnableOwaspDependencyCheck)
		assert.Equal(t, true, configs.EnableShellCheck)
		assert.Equal(t, true, configs.EnableSemanticEngine)
		assert.Equal(t, toolsconfig.Config{
			IsToIgnore: true,
		}, configs.ToolsConfig[tools.GoSec])
		assert.Equal(t, "docker.io/company/go:latest", configs.CustomImages[languages.Go])

		assert.NoError(t, os.Setenv(config.EnvTimeoutInSecondsRequest, "99"))
		assert.NoError(t, os.Setenv(config.EnvTimeoutInSecondsAnalysis, "999"))
		assert.NoError(t, os.Setenv(config.EnvMonitorRetryInSeconds, "20"))
		assert.NoError(t, os.Setenv(config.EnvRepositoryAuthorization, authorization))
		assert.NoError(t, os.Setenv(config.EnvPrintOutputType, "sonarqube"))
		assert.NoError(t, os.Setenv(config.EnvJSONOutputFilePath, filepath.Join(os.TempDir(), "output-sonarqube.json")))
		assert.NoError(t, os.Setenv(config.EnvSeveritiesToIgnore, "INFO"))
		assert.NoError(t, os.Setenv(config.EnvFilesOrPathsToIgnore, "**/*_test.go, **/*_mock.go"))
		assert.NoError(t, os.Setenv(config.EnvReturnErrorIfFoundVulnerability, "false"))
		assert.NoError(t, os.Setenv(config.EnvProjectPath, "./horusec-manager"))
		assert.NoError(t, os.Setenv(config.EnvEnableGitHistoryAnalysis, "false"))
		assert.NoError(t, os.Setenv(config.EnvCertInsecureSkipVerify, "false"))
		assert.NoError(t, os.Setenv(config.EnvEnableCommitAuthor, "false"))
		assert.NoError(t, os.Setenv(config.EnvRepositoryName, "my-project"))
		assert.NoError(t, os.Setenv(config.EnvFalsePositiveHashes, "hash9, hash8"))
		assert.NoError(t, os.Setenv(config.EnvRiskAcceptHashes, "hash7, hash6"))
		assert.NoError(t, os.Setenv(config.EnvHeaders, "{\"x-auth\": \"987654321\"}"))
		assert.NoError(t, os.Setenv(config.EnvContainerBindProjectPath, "./my-path"))
		assert.NoError(t, os.Setenv(config.EnvDisableDocker, "true"))
		assert.NoError(t, os.Setenv(config.EnvCustomRulesPath, "test"))
		assert.NoError(t, os.Setenv(config.EnvEnableInformationSeverity, "true"))
		assert.NoError(t, os.Setenv(config.EnvEnableOwaspDependencyCheck, "true"))
		assert.NoError(t, os.Setenv(config.EnvEnableShellCheck, "true"))
		assert.NoError(t, os.Setenv(config.EnvEnableSemanticEngine, "false"))
		assert.NoError(t, os.Setenv(config.EnvShowVulnerabilitiesTypes, fmt.Sprintf("%s, %s", vulnerability.Vulnerability.ToString(), vulnerability.RiskAccepted.ToString())))
		configs.LoadFromEnvironmentVariables()
		assert.Equal(t, configFilePath, configs.ConfigFilePath)
		assert.Equal(t, int64(99), configs.TimeoutInSecondsRequest)
		assert.Equal(t, int64(999), configs.TimeoutInSecondsAnalysis)
		assert.Equal(t, int64(20), configs.MonitorRetryInSeconds)
		assert.Equal(t, authorization, configs.RepositoryAuthorization)
		assert.Equal(t, "sonarqube", configs.PrintOutputType)
		assert.Equal(t, filepath.Join(os.TempDir(), "output-sonarqube.json"), configs.JSONOutputFilePath)
		assert.Equal(t, []string{"INFO"}, configs.SeveritiesToIgnore)
		assert.Equal(t, []string{"**/*_test.go", "**/*_mock.go"}, configs.FilesOrPathsToIgnore)
		assert.Equal(t, false, configs.ReturnErrorIfFoundVulnerability)
		assert.Equal(t, "./horusec-manager", configs.ProjectPath)
		assert.Equal(t, workdir.Default(), configs.WorkDir)
		assert.Equal(t, false, configs.EnableGitHistoryAnalysis)
		assert.Equal(t, false, configs.CertInsecureSkipVerify)
		assert.Equal(t, false, configs.EnableCommitAuthor)
		assert.Equal(t, "my-project", configs.RepositoryName)
		assert.Equal(t, []string{"hash7", "hash6"}, configs.RiskAcceptHashes)
		assert.Equal(t, []string{"hash9", "hash8"}, configs.FalsePositiveHashes)
		assert.Equal(t, []string{vulnerability.Vulnerability.ToString(), vulnerability.RiskAccepted.ToString()}, configs.ShowVulnerabilitiesTypes)
		assert.Equal(t, map[string]string{"x-auth": "987654321"}, configs.Headers)
		assert.Equal(t, "./my-path", configs.ContainerBindProjectPath)
		assert.Equal(t, true, configs.DisableDocker)
		assert.Equal(t, "test", configs.CustomRulesPath)
		assert.Equal(t, true, configs.EnableInformationSeverity)
		assert.Equal(t, true, configs.EnableOwaspDependencyCheck)
		assert.Equal(t, true, configs.EnableShellCheck)
		assert.Equal(t, false, configs.EnableSemanticEngine)

		logger.LogSetOutput(io.Discard)
		startCmd := start.NewStartCommand(configs)

		cobraCmd := startCmd.CreateStartCommand()
		cobraCmd.PersistentPreRunE = configs.PersistentPreRun

		target, err := os.MkdirTemp(os.TempDir(), "testing-target")
		assert.NoError(t, err)
		repositoryAuthorization := uuid.New().String()
		wd, err := os.Getwd()
		assert.Nil(t, err)
		args := []string{
			"-p", target,
			"-F", "SOMEHASHALEATORY1,SOMEHASHALEATORY2",
			"-R", "SOMEHASHALEATORY3,SOMEHASHALEATORY4",
			"-t", "123",
			"I", "true",
			"--show-vulnerabilities-types", "False Positive,Corrected",
			"--authorization", repositoryAuthorization,
			"--certificate-path", target,
			"--container-bind-project-path", "container-bind-project-path-test",
			"--custom-rules-path", "custom-rules-path-test",
			"--disable-docker", "true",
			"--enable-commit-author", "true",
			"--enable-git-history", "true",
			"--enable-owasp-dependency-check", "true",
			"--enable-shellcheck", "true",
			"--headers", "X-Auth-Service=my-value",
			"--horusec-url", "http://horusec-url-test.com",
			"--ignore", "ignore-test-1,ignore-test-2",
			"--insecure-skip-verify", "true",
			"--json-output-file", "./tmp/json-output-file-test.json",
			"--monitor-retry-count", "123",
			"--output-format", "json",
			"--repository-name", "repository-name-test",
			"--request-timeout", "123",
			"--return-error", "true",
			"--engine.enable-semantic", "true",
		}
		assert.NoError(t, cobraCmd.PersistentFlags().Parse(args))
		assert.NoError(t, cobraCmd.Execute())

		assert.Equal(t, target, configs.ProjectPath)
		assert.Equal(t, []string{"SOMEHASHALEATORY1", "SOMEHASHALEATORY2"}, configs.FalsePositiveHashes)
		assert.Equal(t, []string{"SOMEHASHALEATORY3", "SOMEHASHALEATORY4"}, configs.RiskAcceptHashes)
		assert.Equal(t, []string{vulnerability.FalsePositive.ToString(), vulnerability.Corrected.ToString()}, configs.ShowVulnerabilitiesTypes)
		assert.Equal(t, int64(123), configs.TimeoutInSecondsAnalysis)
		assert.Equal(t, true, configs.EnableInformationSeverity)
		assert.Equal(t, repositoryAuthorization, configs.RepositoryAuthorization)
		assert.Equal(t, target, configs.CertPath)
		assert.Equal(t, "container-bind-project-path-test", configs.ContainerBindProjectPath)
		assert.Equal(t, "custom-rules-path-test", configs.CustomRulesPath)
		assert.Equal(t, true, configs.DisableDocker)
		assert.Equal(t, true, configs.EnableCommitAuthor)
		assert.Equal(t, true, configs.EnableGitHistoryAnalysis)
		assert.Equal(t, true, configs.EnableOwaspDependencyCheck)
		assert.Equal(t, true, configs.EnableShellCheck)
		assert.Equal(t, map[string]string{"X-Auth-Service": "my-value"}, configs.Headers)
		assert.Equal(t, "http://horusec-url-test.com", configs.HorusecAPIUri)
		assert.Equal(t, []string{"ignore-test-1", "ignore-test-2"}, configs.FilesOrPathsToIgnore)
		assert.Equal(t, true, configs.CertInsecureSkipVerify)
		assert.Equal(t, filepath.Join(wd, "tmp", "json-output-file-test.json"), configs.JSONOutputFilePath)
		assert.Equal(t, int64(123), configs.MonitorRetryInSeconds)
		assert.Equal(t, "json", configs.PrintOutputType)
		assert.Equal(t, "repository-name-test", configs.RepositoryName)
		assert.Equal(t, int64(123), configs.TimeoutInSecondsRequest)
		assert.Equal(t, true, configs.ReturnErrorIfFoundVulnerability)
		assert.Equal(t, true, configs.EnableSemanticEngine)
	})
}

func TestNormalizeConfigs(t *testing.T) {
	t.Run("Should success normalize config", func(t *testing.T) {
		cfg := config.New()
		cfg.JSONOutputFilePath = "cli"
		cfg.ProjectPath = "cli"
		cfg.ConfigFilePath = "cli"
		cfg.LogFilePath = "cli"
		wd, err := os.Getwd()
		assert.Nil(t, err)
		expectedJSONOutputFilePath := filepath.Join(wd, cfg.JSONOutputFilePath)
		expectedProjectPath := filepath.Join(wd, cfg.ProjectPath)
		expectedConfigFilePath := filepath.Join(wd, cfg.ConfigFilePath)
		expectedLogFilePath := filepath.Join(wd, cfg.LogFilePath)
		cfg = cfg.Normalize()
		assert.NotEmpty(t, cfg)
		assert.Equal(t, expectedJSONOutputFilePath, cfg.JSONOutputFilePath)
		assert.Equal(t, expectedProjectPath, cfg.ProjectPath)
		assert.Equal(t, expectedConfigFilePath, cfg.ConfigFilePath)
		assert.Equal(t, expectedLogFilePath, cfg.LogFilePath)
	})
}

func TestConfig_Bytes(t *testing.T) {
	t.Run("Should success when parse config to json bytes", func(t *testing.T) {
		viper.Reset()
		repositoryAuthorization := uuid.New().String()
		wd, err := os.Getwd()
		assert.Nil(t, err)
		assert.NoError(t, os.Setenv(config.EnvHorusecAPIUri, "api-uri"))
		assert.NoError(t, os.Setenv(config.EnvCertPath, "cert-path"))
		assert.NoError(t, os.Setenv(config.EnvTimeoutInSecondsRequest, "99"))
		assert.NoError(t, os.Setenv(config.EnvTimeoutInSecondsAnalysis, "999"))
		assert.NoError(t, os.Setenv(config.EnvMonitorRetryInSeconds, "20"))
		assert.NoError(t, os.Setenv(config.EnvRepositoryAuthorization, repositoryAuthorization))
		assert.NoError(t, os.Setenv(config.EnvPrintOutputType, "sonarqube"))
		assert.NoError(t, os.Setenv(config.EnvJSONOutputFilePath, filepath.Join(os.TempDir(), "output-sonarqube.json")))
		assert.NoError(t, os.Setenv(config.EnvSeveritiesToIgnore, "INFO"))
		assert.NoError(t, os.Setenv(config.EnvFilesOrPathsToIgnore, "**/*_test.go, **/*_mock.go"))
		assert.NoError(t, os.Setenv(config.EnvReturnErrorIfFoundVulnerability, "false"))
		assert.NoError(t, os.Setenv(config.EnvProjectPath, "./horusec-manager"))
		assert.NoError(t, os.Setenv(config.EnvEnableGitHistoryAnalysis, "false"))
		assert.NoError(t, os.Setenv(config.EnvCertInsecureSkipVerify, "false"))
		assert.NoError(t, os.Setenv(config.EnvEnableCommitAuthor, "false"))
		assert.NoError(t, os.Setenv(config.EnvRepositoryName, "my-project"))
		assert.NoError(t, os.Setenv(config.EnvFalsePositiveHashes, "hash9, hash8"))
		assert.NoError(t, os.Setenv(config.EnvRiskAcceptHashes, "hash7, hash6"))
		assert.NoError(t, os.Setenv(config.EnvHeaders, "{\"x-auth\": \"987654321\"}"))
		assert.NoError(t, os.Setenv(config.EnvContainerBindProjectPath, "./my-path"))
		assert.NoError(t, os.Setenv(config.EnvDisableDocker, "true"))
		assert.NoError(t, os.Setenv(config.EnvCustomRulesPath, "test"))
		assert.NoError(t, os.Setenv(config.EnvEnableInformationSeverity, "true"))
		assert.NoError(t, os.Setenv(config.EnvEnableOwaspDependencyCheck, "true"))
		assert.NoError(t, os.Setenv(config.EnvEnableShellCheck, "true"))
		assert.NoError(t, os.Setenv(config.EnvShowVulnerabilitiesTypes, fmt.Sprintf("%s, %s", vulnerability.Vulnerability.ToString(), vulnerability.RiskAccepted.ToString())))
		assert.NoError(t, os.Setenv(config.EnvLogFilePath, "batata"))
		cfg := config.New().LoadFromEnvironmentVariables()

		expectedOutput := `{
  "is_timeout": false,
  "log_level": "info",
  "config_file_path": "` + filepath.Join(wd, "horusec-config.json") + `",
  "log_file_path": "batata",
  "horusec_api_uri": "api-uri",
  "repository_authorization": "` + repositoryAuthorization + `",
  "cert_path": "cert-path",
  "repository_name": "my-project",
  "print_output_type": "sonarqube",
  "json_output_file_path": "` + filepath.Join(os.TempDir(), "output-sonarqube.json") + `",
  "project_path": "./horusec-manager",
  "custom_rules_path": "test",
  "container_bind_project_path": "./my-path",
  "timeout_in_seconds_request": 99,
  "timeout_in_seconds_analysis": 999,
  "monitor_retry_in_seconds": 20,
  "return_error_if_found_vulnerability": false,
  "enable_git_history_analysis": false,
  "cert_insecure_skip_verify": false,
  "enable_commit_author": false,
  "disable_docker": true,
  "enable_information_severity": true,
  "enable_owasp_dependency_check": true,
  "enable_shell_check": true,
  "enable_semantic_engine": false,
  "severities_to_ignore": [
    "INFO"
  ],
  "files_or_paths_to_ignore": [
    "**/*_test.go",
    "**/*_mock.go"
  ],
  "false_positive_hashes": [
    "hash9",
    "hash8"
  ],
  "risk_accept_hashes": [
    "hash7",
    "hash6"
  ],
  "show_vulnerabilities_types": [
    "Vulnerability",
    "Risk Accepted"
  ],
  "tools_config": {
    "Bandit": {
      "istoignore": false
    },
    "Brakeman": {
      "istoignore": false
    },
    "BundlerAudit": {
      "istoignore": false
    },
    "Checkov": {
      "istoignore": false
    },
    "DotnetCli": {
      "istoignore": false
    },
    "Flawfinder": {
      "istoignore": false
    },
    "GitLeaks": {
      "istoignore": false
    },
    "GoSec": {
      "istoignore": false
    },
    "HorusecEngine": {
      "istoignore": false
    },
    "MixAudit": {
      "istoignore": false
    },
    "Nancy": {
      "istoignore": false
    },
    "NpmAudit": {
      "istoignore": false
    },
    "OwaspDependencyCheck": {
      "istoignore": false
    },
    "PhpCS": {
      "istoignore": false
    },
    "Safety": {
      "istoignore": false
    },
    "SecurityCodeScan": {
      "istoignore": false
    },
    "Semgrep": {
      "istoignore": false
    },
    "ShellCheck": {
      "istoignore": false
    },
    "Sobelow": {
      "istoignore": false
    },
    "TfSec": {
      "istoignore": false
    },
    "Trivy": {
      "istoignore": false
    },
    "YarnAudit": {
      "istoignore": false
    }
  },
  "headers": {
    "x-auth": "987654321"
  },
  "work_dir": {
    "go": [],
    "csharp": [],
    "ruby": [],
    "python": [],
    "java": [],
    "kotlin": [],
    "javaScript": [],
    "leaks": [],
    "hcl": [],
    "php": [],
    "c": [],
    "yaml": [],
    "generic": [],
    "elixir": [],
    "shell": [],
    "dart": [],
    "nginx": []
  },
  "custom_images": {
    "c": "",
    "csharp": "",
    "elixir": "",
    "generic": "",
    "go": "",
    "hcl": "",
    "javascript": "",
    "leaks": "",
    "php": "",
    "python": "",
    "ruby": "",
    "shell": ""
  },
  "version": "{{VERSION_NOT_FOUND}}"
}`
		// Add scape slashes when running on Windows.
		expectedOutput = strings.ReplaceAll(expectedOutput, `\`, `\\`)
		assert.Equal(t, expectedOutput, string(cfg.Bytes()))
	})
	t.Run("Should have the predefined schema", func(t *testing.T) {
		expectedConfig := []byte(`{
  "is_timeout": false,
  "log_level": "",
  "config_file_path": "",
  "log_file_path": "",
  "horusec_api_uri": "",
  "repository_authorization": "",
  "cert_path": "",
  "repository_name": "",
  "print_output_type": "",
  "json_output_file_path": "",
  "project_path": "",
  "custom_rules_path": "",
  "container_bind_project_path": "",
  "timeout_in_seconds_request": 0,
  "timeout_in_seconds_analysis": 0,
  "monitor_retry_in_seconds": 0,
  "return_error_if_found_vulnerability": false,
  "enable_git_history_analysis": false,
  "cert_insecure_skip_verify": false,
  "enable_commit_author": false,
  "disable_docker": false,
  "enable_information_severity": false,
  "enable_owasp_dependency_check": false,
  "enable_shell_check": false,
  "enable_semantic_engine": false,
  "severities_to_ignore": null,
  "files_or_paths_to_ignore": null,
  "false_positive_hashes": null,
  "risk_accept_hashes": null,
  "show_vulnerabilities_types": null,
  "tools_config": null,
  "headers": null,
  "work_dir": null,
  "custom_images": null,
  "version": ""
}`)
		cfg := config.Config{}
		assert.Equal(t, string(expectedConfig), string(cfg.Bytes()))
	})
}

func TestSetLogOutput(t *testing.T) {
	t.Run("Should success when log path is empty", func(t *testing.T) {
		cfg := config.New()
		err := cfg.ConfigureLogger()
		assert.NoError(t, err)
	})
	t.Run("Should success when log path is valid", func(t *testing.T) {
		file, err := os.CreateTemp(os.TempDir(), "log-test")
		assert.NoError(t, err)

		cfg := config.New()
		cfg.LogFilePath = file.Name()
		err = cfg.ConfigureLogger()
		assert.NoError(t, err)
	})
}
