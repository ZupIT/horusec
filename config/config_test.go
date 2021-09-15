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
		assert.Equal(t, "{{VERSION_NOT_FOUND}}", configs.GetVersion())
		assert.Equal(t, "http://0.0.0.0:8000", configs.GetHorusecAPIUri())
		assert.Equal(t, int64(300), configs.GetTimeoutInSecondsRequest())
		assert.Equal(t, int64(600), configs.GetTimeoutInSecondsAnalysis())
		assert.Equal(t, int64(15), configs.GetMonitorRetryInSeconds())
		assert.Equal(t, uuid.Nil.String(), configs.GetRepositoryAuthorization())
		assert.Equal(t, "", configs.GetPrintOutputType())
		assert.Equal(t, "", configs.GetJSONOutputFilePath())
		assert.Equal(t, 1, len(configs.GetSeveritiesToIgnore()))
		assert.Equal(t, 2, len(configs.GetFilesOrPathsToIgnore()))
		assert.Equal(t, false, configs.GetReturnErrorIfFoundVulnerability())
		assert.Equal(t, currentPath, configs.GetProjectPath())
		assert.Equal(t, workdir.NewWorkDir(), configs.GetWorkDir())
		assert.Equal(t, false, configs.GetEnableGitHistoryAnalysis())
		assert.Equal(t, false, configs.GetCertInsecureSkipVerify())
		assert.Equal(t, "", configs.GetCertPath())
		assert.Equal(t, false, configs.GetEnableCommitAuthor())
		assert.Equal(t, "config", configs.GetRepositoryName())
		assert.Equal(t, 0, len(configs.GetRiskAcceptHashes()))
		assert.Equal(t, 0, len(configs.GetFalsePositiveHashes()))
		assert.Equal(t, 0, len(configs.GetHeaders()))
		assert.Equal(t, "", configs.GetContainerBindProjectPath())
		assert.Equal(t, true, configs.IsEmptyRepositoryAuthorization())
		assert.Equal(t, 22, len(configs.GetToolsConfig()))
		assert.Equal(t, false, configs.GetDisableDocker())
		assert.Equal(t, "", configs.GetCustomRulesPath())
		assert.Equal(t, false, configs.GetEnableInformationSeverity())
		assert.Equal(t, 12, len(configs.GetCustomImages()))
		assert.Equal(t, 1, len(configs.GetShowVulnerabilitiesTypes()))
		assert.Equal(t, false, configs.GetEnableOwaspDependencyCheck())
		assert.Equal(t, false, configs.GetEnableShellCheck())
	})
	t.Run("Should change horusec config and return your new values", func(t *testing.T) {
		currentPath, _ := os.Getwd()
		configs := config.New()
		configs.SetConfigFilePath(path.Join(currentPath + "other-horusec-config.json"))
		configs.SetRepositoryAuthorization(uuid.New().String())
		configs.SetPrintOutputType("json")
		configs.SetJSONOutputFilePath("./other-file-path.json")
		configs.SetSeveritiesToIgnore([]string{"info"})
		configs.SetProjectPath("./some-other-file-path")
		configs.SetWorkDir(map[string]interface{}{"csharp": []string{"test"}})
		configs.SetEnableGitHistoryAnalysis(true)
		configs.SetCertInsecureSkipVerify(true)
		configs.SetCertPath("./certs")
		configs.SetEnableCommitAuthor(true)
		configs.SetRiskAcceptHashes([]string{"123456789"})
		configs.SetFalsePositiveHashes([]string{"987654321"})
		configs.SetHeaders(map[string]string{"x-header": "value"})
		configs.SetToolsConfig(toolsconfig.MapToolConfig{tools.Sobelow: {IsToIgnore: true}})
		configs.SetCustomRulesPath("test")
		configs.SetEnableOwaspDependencyCheck(true)
		configs.SetEnableShellCheck(true)

		assert.NotEqual(t, uuid.Nil.String(), configs.GetRepositoryAuthorization())
		assert.NotEqual(t, "text", configs.GetPrintOutputType())
		assert.NotEqual(t, "", configs.GetJSONOutputFilePath())
		assert.NotEqual(t, 0, len(configs.GetSeveritiesToIgnore()))
		assert.NotEqual(t, 0, len(configs.GetFilesOrPathsToIgnore()))
		assert.NotEqual(t, currentPath, configs.GetProjectPath())
		assert.NotEqual(t, workdir.NewWorkDir().CSharp, configs.GetWorkDir().CSharp)
		assert.NotEqual(t, false, configs.GetEnableGitHistoryAnalysis())
		assert.NotEqual(t, false, configs.GetCertInsecureSkipVerify())
		assert.NotEqual(t, "", configs.GetCertPath())
		assert.NotEqual(t, false, configs.GetEnableCommitAuthor())
		assert.NotEqual(t, "", configs.GetRepositoryName())
		assert.NotEqual(t, 0, len(configs.GetRiskAcceptHashes()))
		assert.NotEqual(t, 0, len(configs.GetFalsePositiveHashes()))
		assert.NotEqual(t, 0, len(configs.GetHeaders()))
		assert.NotEqual(t, false, configs.GetToolsConfig()[tools.Sobelow])
		assert.Equal(t, "test", configs.GetCustomRulesPath())
		assert.Equal(t, []string{vulnerability.Vulnerability.ToString()}, configs.GetShowVulnerabilitiesTypes())
		assert.NotEqual(t, map[languages.Language]string{}, configs.GetCustomImages())
		assert.Equal(t, true, configs.GetEnableOwaspDependencyCheck())
		assert.Equal(t, true, configs.GetEnableShellCheck())
	})
	t.Run("Should return horusec config using new viper file", func(t *testing.T) {
		viper.Reset()
		currentPath, err := os.Getwd()
		configFilePath := path.Join(currentPath, ".example-horusec-cli.json")
		assert.NoError(t, err)
		configs := config.New()
		configs.SetConfigFilePath(configFilePath)
		configs.MergeFromConfigFile()
		assert.Equal(t, configFilePath, configs.GetConfigFilePath())
		assert.Equal(t, "http://new-viper.horusec.com", configs.GetHorusecAPIUri())
		assert.Equal(t, int64(20), configs.GetTimeoutInSecondsRequest())
		assert.Equal(t, int64(100), configs.GetTimeoutInSecondsAnalysis())
		assert.Equal(t, int64(10), configs.GetMonitorRetryInSeconds())
		assert.Equal(t, "8beffdca-636e-4d73-a22f-b0f7c3cff1c4", configs.GetRepositoryAuthorization())
		assert.Equal(t, "json", configs.GetPrintOutputType())
		assert.Equal(t, "./output.json", configs.GetJSONOutputFilePath())
		assert.Equal(t, []string{"INFO"}, configs.GetSeveritiesToIgnore())
		assert.Equal(t, []string{"./assets"}, configs.GetFilesOrPathsToIgnore())
		assert.Equal(t, true, configs.GetReturnErrorIfFoundVulnerability())
		assert.Equal(t, "./", configs.GetProjectPath())
		assert.Equal(t, workdir.NewWorkDir(), configs.GetWorkDir())
		assert.Equal(t, true, configs.GetEnableGitHistoryAnalysis())
		assert.Equal(t, true, configs.GetCertInsecureSkipVerify())
		assert.Equal(t, "", configs.GetCertPath())
		assert.Equal(t, true, configs.GetEnableCommitAuthor())
		assert.Equal(t, "horus", configs.GetRepositoryName())
		assert.Equal(t, []string{"hash3", "hash4"}, configs.GetRiskAcceptHashes())
		assert.Equal(t, []string{"hash1", "hash2"}, configs.GetFalsePositiveHashes())
		assert.Equal(t, map[string]string{"x-headers": "some-other-value"}, configs.GetHeaders())
		assert.Equal(t, "test", configs.GetContainerBindProjectPath())
		assert.Equal(t, true, configs.GetDisableDocker())
		assert.Equal(t, "test", configs.GetCustomRulesPath())
		assert.Equal(t, true, configs.GetEnableInformationSeverity())
		assert.Equal(t, true, configs.GetEnableOwaspDependencyCheck())
		assert.Equal(t, true, configs.GetEnableShellCheck())
		assert.Equal(t, []string{vulnerability.Vulnerability.ToString(), vulnerability.FalsePositive.ToString()}, configs.GetShowVulnerabilitiesTypes())
		assert.Equal(t, toolsconfig.ToolConfig{
			IsToIgnore: true,
		}, configs.GetToolsConfig()[tools.GoSec])
		assert.Equal(t, "docker.io/company/go:latest", configs.GetCustomImages()["go"])
	})
	t.Run("Should return horusec config using viper file and override by environment", func(t *testing.T) {
		viper.Reset()
		authorization := uuid.New().String()
		currentPath, err := os.Getwd()
		configFilePath := path.Join(currentPath + "/.example-horusec-cli.json")
		assert.NoError(t, err)
		configs := config.New()
		configs.SetConfigFilePath(configFilePath)
		configs.MergeFromConfigFile()
		assert.Equal(t, configFilePath, configs.GetConfigFilePath())
		assert.Equal(t, "http://new-viper.horusec.com", configs.GetHorusecAPIUri())
		assert.Equal(t, int64(20), configs.GetTimeoutInSecondsRequest())
		assert.Equal(t, int64(100), configs.GetTimeoutInSecondsAnalysis())
		assert.Equal(t, int64(10), configs.GetMonitorRetryInSeconds())
		assert.Equal(t, "8beffdca-636e-4d73-a22f-b0f7c3cff1c4", configs.GetRepositoryAuthorization())
		assert.Equal(t, "json", configs.GetPrintOutputType())
		assert.Equal(t, "./output.json", configs.GetJSONOutputFilePath())
		assert.Equal(t, []string{"INFO"}, configs.GetSeveritiesToIgnore())
		assert.Equal(t, []string{"./assets"}, configs.GetFilesOrPathsToIgnore())
		assert.Equal(t, true, configs.GetReturnErrorIfFoundVulnerability())
		assert.Equal(t, "./", configs.GetProjectPath())
		assert.Equal(t, workdir.NewWorkDir(), configs.GetWorkDir())
		assert.Equal(t, true, configs.GetEnableGitHistoryAnalysis())
		assert.Equal(t, true, configs.GetCertInsecureSkipVerify())
		assert.Equal(t, "", configs.GetCertPath())
		assert.Equal(t, true, configs.GetEnableCommitAuthor())
		assert.Equal(t, "horus", configs.GetRepositoryName())
		assert.Equal(t, []string{"hash3", "hash4"}, configs.GetRiskAcceptHashes())
		assert.Equal(t, []string{"hash1", "hash2"}, configs.GetFalsePositiveHashes())
		assert.Equal(t, []string{vulnerability.Vulnerability.ToString(), vulnerability.FalsePositive.ToString()}, configs.GetShowVulnerabilitiesTypes())
		assert.Equal(t, map[string]string{"x-headers": "some-other-value"}, configs.GetHeaders())
		assert.Equal(t, "test", configs.GetContainerBindProjectPath())
		assert.Equal(t, true, configs.GetEnableInformationSeverity())
		assert.Equal(t, true, configs.GetEnableOwaspDependencyCheck())
		assert.Equal(t, true, configs.GetEnableShellCheck())
		assert.Equal(t, toolsconfig.ToolConfig{
			IsToIgnore: true,
		}, configs.GetToolsConfig()[tools.GoSec])
		assert.Equal(t, "docker.io/company/go:latest", configs.GetCustomImages()["go"])

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
		assert.NoError(t, os.Setenv(config.EnvShowVulnerabilitiesTypes, fmt.Sprintf("%s, %s", vulnerability.Vulnerability.ToString(), vulnerability.RiskAccepted.ToString())))
		assert.NoError(t, os.Setenv(config.EnvLogFilePath, "test"))
		configs.MergeFromEnvironmentVariables()
		assert.Equal(t, configFilePath, configs.GetConfigFilePath())
		assert.Equal(t, "http://horusec.com", configs.GetHorusecAPIUri())
		assert.Equal(t, int64(99), configs.GetTimeoutInSecondsRequest())
		assert.Equal(t, int64(999), configs.GetTimeoutInSecondsAnalysis())
		assert.Equal(t, int64(20), configs.GetMonitorRetryInSeconds())
		assert.Equal(t, authorization, configs.GetRepositoryAuthorization())
		assert.Equal(t, "sonarqube", configs.GetPrintOutputType())
		assert.Equal(t, filepath.Join(os.TempDir(), "output-sonarqube.json"), configs.GetJSONOutputFilePath())
		assert.Equal(t, []string{"INFO"}, configs.GetSeveritiesToIgnore())
		assert.Equal(t, []string{"**/*_test.go", "**/*_mock.go"}, configs.GetFilesOrPathsToIgnore())
		assert.Equal(t, false, configs.GetReturnErrorIfFoundVulnerability())
		assert.Equal(t, "./horusec-manager", configs.GetProjectPath())
		assert.Equal(t, workdir.NewWorkDir(), configs.GetWorkDir())
		assert.Equal(t, false, configs.GetEnableGitHistoryAnalysis())
		assert.Equal(t, false, configs.GetCertInsecureSkipVerify())
		assert.Equal(t, "./", configs.GetCertPath())
		assert.Equal(t, false, configs.GetEnableCommitAuthor())
		assert.Equal(t, "my-project", configs.GetRepositoryName())
		assert.Equal(t, []string{"hash7", "hash6"}, configs.GetRiskAcceptHashes())
		assert.Equal(t, []string{"hash9", "hash8"}, configs.GetFalsePositiveHashes())
		assert.Equal(t, map[string]string{"x-auth": "987654321"}, configs.GetHeaders())
		assert.Equal(t, "./my-path", configs.GetContainerBindProjectPath())
		assert.Equal(t, true, configs.GetDisableDocker())
		assert.Equal(t, "test", configs.GetCustomRulesPath())
		assert.Equal(t, true, configs.GetEnableInformationSeverity())
		assert.Equal(t, true, configs.GetEnableOwaspDependencyCheck())
		assert.Equal(t, true, configs.GetEnableShellCheck())
		assert.Equal(t, []string{vulnerability.Vulnerability.ToString(), vulnerability.RiskAccepted.ToString()}, configs.GetShowVulnerabilitiesTypes())
	})
	t.Run("Should return horusec config using viper file and override by environment and override by flags", func(t *testing.T) {
		viper.Reset()
		authorization := uuid.New().String()
		currentPath, err := os.Getwd()
		configFilePath := path.Join(currentPath, ".example-horusec-cli.json")
		assert.NoError(t, err)
		configs := config.New()
		configs.SetConfigFilePath(configFilePath)
		configs.MergeFromConfigFile()
		assert.Equal(t, configFilePath, configs.GetConfigFilePath())
		assert.Equal(t, "http://new-viper.horusec.com", configs.GetHorusecAPIUri())
		assert.Equal(t, int64(20), configs.GetTimeoutInSecondsRequest())
		assert.Equal(t, int64(100), configs.GetTimeoutInSecondsAnalysis())
		assert.Equal(t, int64(10), configs.GetMonitorRetryInSeconds())
		assert.Equal(t, "8beffdca-636e-4d73-a22f-b0f7c3cff1c4", configs.GetRepositoryAuthorization())
		assert.Equal(t, "json", configs.GetPrintOutputType())
		assert.Equal(t, "./output.json", configs.GetJSONOutputFilePath())
		assert.Equal(t, []string{"INFO"}, configs.GetSeveritiesToIgnore())
		assert.Equal(t, []string{"./assets"}, configs.GetFilesOrPathsToIgnore())
		assert.Equal(t, true, configs.GetReturnErrorIfFoundVulnerability())
		assert.Equal(t, "./", configs.GetProjectPath())
		assert.Equal(t, workdir.NewWorkDir(), configs.GetWorkDir())
		assert.Equal(t, true, configs.GetEnableGitHistoryAnalysis())
		assert.Equal(t, true, configs.GetCertInsecureSkipVerify())
		assert.Equal(t, "", configs.GetCertPath())
		assert.Equal(t, true, configs.GetEnableCommitAuthor())
		assert.Equal(t, "horus", configs.GetRepositoryName())
		assert.Equal(t, []string{"hash3", "hash4"}, configs.GetRiskAcceptHashes())
		assert.Equal(t, []string{"hash1", "hash2"}, configs.GetFalsePositiveHashes())
		assert.Equal(t, []string{vulnerability.Vulnerability.ToString(), vulnerability.FalsePositive.ToString()}, configs.GetShowVulnerabilitiesTypes())
		assert.Equal(t, map[string]string{"x-headers": "some-other-value"}, configs.GetHeaders())
		assert.Equal(t, "test", configs.GetContainerBindProjectPath())
		assert.Equal(t, true, configs.GetEnableInformationSeverity())
		assert.Equal(t, true, configs.GetEnableOwaspDependencyCheck())
		assert.Equal(t, true, configs.GetEnableShellCheck())
		assert.Equal(t, toolsconfig.ToolConfig{
			IsToIgnore: true,
		}, configs.GetToolsConfig()[tools.GoSec])
		assert.Equal(t, "docker.io/company/go:latest", configs.GetCustomImages()["go"])

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
		assert.Equal(t, configFilePath, configs.GetConfigFilePath())
		assert.Equal(t, int64(99), configs.GetTimeoutInSecondsRequest())
		assert.Equal(t, int64(999), configs.GetTimeoutInSecondsAnalysis())
		assert.Equal(t, int64(20), configs.GetMonitorRetryInSeconds())
		assert.Equal(t, authorization, configs.GetRepositoryAuthorization())
		assert.Equal(t, "sonarqube", configs.GetPrintOutputType())
		assert.Equal(t, filepath.Join(os.TempDir(), "output-sonarqube.json"), configs.GetJSONOutputFilePath())
		assert.Equal(t, []string{"INFO"}, configs.GetSeveritiesToIgnore())
		assert.Equal(t, []string{"**/*_test.go", "**/*_mock.go"}, configs.GetFilesOrPathsToIgnore())
		assert.Equal(t, false, configs.GetReturnErrorIfFoundVulnerability())
		assert.Equal(t, "./horusec-manager", configs.GetProjectPath())
		assert.Equal(t, workdir.NewWorkDir(), configs.GetWorkDir())
		assert.Equal(t, false, configs.GetEnableGitHistoryAnalysis())
		assert.Equal(t, false, configs.GetCertInsecureSkipVerify())
		assert.Equal(t, false, configs.GetEnableCommitAuthor())
		assert.Equal(t, "my-project", configs.GetRepositoryName())
		assert.Equal(t, []string{"hash7", "hash6"}, configs.GetRiskAcceptHashes())
		assert.Equal(t, []string{"hash9", "hash8"}, configs.GetFalsePositiveHashes())
		assert.Equal(t, []string{vulnerability.Vulnerability.ToString(), vulnerability.RiskAccepted.ToString()}, configs.GetShowVulnerabilitiesTypes())
		assert.Equal(t, map[string]string{"x-auth": "987654321"}, configs.GetHeaders())
		assert.Equal(t, "./my-path", configs.GetContainerBindProjectPath())
		assert.Equal(t, true, configs.GetDisableDocker())
		assert.Equal(t, "test", configs.GetCustomRulesPath())
		assert.Equal(t, true, configs.GetEnableInformationSeverity())
		assert.Equal(t, true, configs.GetEnableOwaspDependencyCheck())
		assert.Equal(t, true, configs.GetEnableShellCheck())

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

		assert.Equal(t, target, configs.GetProjectPath())
		assert.Equal(t, []string{"SOMEHASHALEATORY1", "SOMEHASHALEATORY2"}, configs.GetFalsePositiveHashes())
		assert.Equal(t, []string{"SOMEHASHALEATORY3", "SOMEHASHALEATORY4"}, configs.GetRiskAcceptHashes())
		assert.Equal(t, []string{vulnerability.Vulnerability.ToString()}, configs.GetShowVulnerabilitiesTypes())
		assert.Equal(t, int64(1000), configs.GetTimeoutInSecondsAnalysis())
		assert.Equal(t, true, configs.GetEnableInformationSeverity())
	})
}

func TestNormalizeConfigs(t *testing.T) {
	t.Run("Should success normalize config", func(t *testing.T) {
		config := config.New()
		config.SetJSONOutputFilePath("./cli")
		config.SetProjectPath("./cli")

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
