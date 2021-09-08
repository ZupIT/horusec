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
	"testing"

	"github.com/ZupIT/horusec-devkit/pkg/enums/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec/cmd/app/start"
	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/entities/workdir"
)

func TestMain(m *testing.M) {
	_ = os.RemoveAll("./tmp")
	_ = os.MkdirAll("./tmp", 0750)
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
		assert.Equal(t, workdir.NewWorkDir(), configs.WorkDir)
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
	})
	t.Run("Should change horusec config and return your new values", func(t *testing.T) {
		currentPath, _ := os.Getwd()
		configs := config.New()
		configs.ConfigFilePath = path.Join(currentPath + "other-horusec-config.json")
		configs.RepositoryAuthorization = uuid.New().String()
		configs.PrintOutputType = "json"
		configs.JSONOutputFilePath = "./other-file-path.json"
		configs.SeveritiesToIgnore = []string{"info"}
		configs.ProjectPath = "./some-other-file-path"
		configs.WorkDir = workdir.NewWorkDir().ParseInterfaceToStruct(map[string]interface{}{"csharp": []string{"test"}})
		configs.EnableGitHistoryAnalysis = (true)
		configs.CertInsecureSkipVerify = true
		configs.CertPath = "./certs"
		configs.EnableCommitAuthor = (true)
		configs.RiskAcceptHashes = ([]string{"123456789"})
		configs.FalsePositiveHashes = []string{"987654321"}
		configs.Headers = map[string]string{"x-header": "value"}
		configs.ToolsConfig = toolsconfig.ParseInterfaceToMapToolsConfig(
			toolsconfig.MapToolConfig{tools.Sobelow: {IsToIgnore: true}},
		)
		configs.CustomRulesPath = "test"
		configs.EnableOwaspDependencyCheck = true
		configs.EnableShellCheck = true

		assert.NotEqual(t, uuid.Nil.String(), configs.RepositoryAuthorization)
		assert.NotEqual(t, "text", configs.PrintOutputType)
		assert.NotEqual(t, "", configs.JSONOutputFilePath)
		assert.NotEqual(t, 0, len(configs.SeveritiesToIgnore))
		assert.NotEqual(t, 0, len(configs.FilesOrPathsToIgnore))
		assert.NotEqual(t, currentPath, configs.ProjectPath)
		assert.NotEqual(t, workdir.NewWorkDir().CSharp, configs.WorkDir.CSharp)
		assert.NotEqual(t, false, configs.EnableGitHistoryAnalysis)
		assert.NotEqual(t, false, configs.CertInsecureSkipVerify)
		assert.NotEqual(t, "", configs.CertPath)
		assert.NotEqual(t, false, configs.EnableCommitAuthor)
		assert.NotEqual(t, "", configs.RepositoryName)
		assert.NotEqual(t, 0, len(configs.RiskAcceptHashes))
		assert.NotEqual(t, 0, len(configs.FalsePositiveHashes))
		assert.NotEqual(t, 0, len(configs.Headers))
		assert.NotEqual(t, false, configs.ToolsConfig[tools.Sobelow])
		assert.Equal(t, "test", configs.CustomRulesPath)
		assert.Equal(t, []string{vulnerability.Vulnerability.ToString()}, configs.ShowVulnerabilitiesTypes)
		assert.NotEqual(t, map[languages.Language]string{}, configs.CustomImages)
		assert.Equal(t, true, configs.EnableOwaspDependencyCheck)
		assert.Equal(t, true, configs.EnableShellCheck)
	})
	t.Run("Should return horusec config using new viper file", func(t *testing.T) {
		viper.Reset()
		currentPath, err := os.Getwd()
		configFilePath := path.Join(currentPath, ".example-horusec-cli.json")
		assert.NoError(t, err)
		configs := config.New()
		configs.ConfigFilePath = configFilePath
		configs.MergeFromConfigFile()
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
		assert.Equal(t, workdir.NewWorkDir(), configs.WorkDir)
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
		assert.Equal(t, toolsconfig.ToolConfig{
			IsToIgnore: true,
		}, configs.ToolsConfig[tools.GoSec])
		assert.Equal(t, "docker.io/company/go:latest", configs.CustomImages["go"])
	})
	t.Run("Should return horusec config using viper file and override by environment", func(t *testing.T) {
		viper.Reset()
		authorization := uuid.New().String()
		currentPath, err := os.Getwd()
		configFilePath := path.Join(currentPath + "/.example-horusec-cli.json")
		assert.NoError(t, err)
		configs := config.New()
		configs.ConfigFilePath = configFilePath
		configs.MergeFromConfigFile()
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
		assert.Equal(t, workdir.NewWorkDir(), configs.WorkDir)
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
		assert.Equal(t, toolsconfig.ToolConfig{
			IsToIgnore: true,
		}, configs.ToolsConfig[tools.GoSec])
		assert.Equal(t, "docker.io/company/go:latest", configs.CustomImages["go"])

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
		assert.NoError(t, os.Setenv(config.EnvLogFilePath, "test"))
		configs.MergeFromEnvironmentVariables()

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
		assert.Equal(t, workdir.NewWorkDir(), configs.WorkDir)
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
		assert.Equal(
			t,
			[]string{vulnerability.Vulnerability.ToString(), vulnerability.FalsePositive.ToString()},
			configs.ShowVulnerabilitiesTypes,
		)
	})
	t.Run("Should return horusec config using viper file and override by environment and override by flags", func(t *testing.T) {
		viper.Reset()
		authorization := uuid.New().String()
		currentPath, err := os.Getwd()
		configFilePath := path.Join(currentPath, ".example-horusec-cli.json")
		assert.NoError(t, err)
		configs := config.New()
		configs.ConfigFilePath = configFilePath
		configs.MergeFromConfigFile()
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
		assert.Equal(t, workdir.NewWorkDir(), configs.WorkDir)
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
		assert.Equal(t, toolsconfig.ToolConfig{
			IsToIgnore: true,
		}, configs.ToolsConfig[tools.GoSec])
		assert.Equal(t, "docker.io/company/go:latest", configs.CustomImages["go"])

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
		assert.NoError(t, os.Setenv(config.EnvShowVulnerabilitiesTypes, fmt.Sprintf("%s, %s", vulnerability.Vulnerability.ToString(), vulnerability.RiskAccepted.ToString())))
		configs.MergeFromEnvironmentVariables()
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
		assert.Equal(t, workdir.NewWorkDir(), configs.WorkDir)
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

		logger.LogSetOutput(io.Discard)
		startCmd := start.NewStartCommand(configs)

		cobraCmd := startCmd.CreateStartCommand()
		// Remove the pre run hook to override the output
		cobraCmd.PreRunE = nil

		target, err := os.MkdirTemp(os.TempDir(), "testing-target")
		assert.NoError(t, err)

		args := []string{
			"-p", target,
			"-F", "SOMEHASHALEATORY1,SOMEHASHALEATORY2",
			"-R", "SOMEHASHALEATORY3,SOMEHASHALEATORY4",
			"-t", "1000",
			"I", "true",
			"--show-vulnerabilities-types", "Vulnerability",
		}
		assert.NoError(t, cobraCmd.PersistentFlags().Parse(args))
		assert.NoError(t, cobraCmd.Execute())

		assert.Equal(t, target, configs.ProjectPath)
		assert.Equal(t, []string{"SOMEHASHALEATORY1", "SOMEHASHALEATORY2"}, configs.FalsePositiveHashes)
		assert.Equal(t, []string{"SOMEHASHALEATORY3", "SOMEHASHALEATORY4"}, configs.RiskAcceptHashes)
		assert.Equal(t, []string{vulnerability.Vulnerability.ToString()}, configs.ShowVulnerabilitiesTypes)
		assert.Equal(t, int64(1000), configs.TimeoutInSecondsAnalysis)
		assert.Equal(t, true, configs.EnableInformationSeverity)
	})
}

func TestNormalizeConfigs(t *testing.T) {
	t.Run("Should success normalize config", func(t *testing.T) {
		config := config.New()
		config.JSONOutputFilePath = "./cli"
		config.ProjectPath = "./cli"

		assert.NotEmpty(t, config.Normalize())
	})
}

func TestConfig_ToBytes(t *testing.T) {
	t.Run("Should success when parse config to json bytes without indent", func(t *testing.T) {
		config := config.New().MergeFromEnvironmentVariables()
		assert.NotEmpty(t, config.ToBytes(false))
	})
	t.Run("Should success when parse config to json bytes with indent", func(t *testing.T) {
		config := config.New().MergeFromEnvironmentVariables()
		assert.NotEmpty(t, config.ToBytes(true))
	})
}
func TestSetLogOutput(t *testing.T) {
	t.Run("Should success when log path is empty", func(t *testing.T) {
		config := config.New()
		err := config.Eval()
		assert.NoError(t, err)
	})
	t.Run("Should success when log path is valid", func(t *testing.T) {
		file, err := os.CreateTemp(os.TempDir(), "log-test")
		assert.NoError(t, err)

		config := config.New()
		config.LogFilePath = file.Name()
		err = config.Eval()
		assert.NoError(t, err)
	})

}
