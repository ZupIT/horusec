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

package config

import (
	"github.com/ZupIT/horusec/horusec-cli/internal/entities/workdir"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewHorusecConfig(t *testing.T) {
	//	wd := &workdir.WorkDir{}
	t.Run("Should return horusec config with your default values", func(t *testing.T) {
		currentPath, _ := os.Getwd()
		configs := &Config{}
		configs.NewConfigsFromEnvironments()
		assert.Equal(t, "", configs.GetConfigFilePath())
		assert.Equal(t, "http://0.0.0.0:8000", configs.GetHorusecAPIUri())
		assert.Equal(t, int64(300), configs.GetTimeoutInSecondsRequest())
		assert.Equal(t, int64(600), configs.GetTimeoutInSecondsAnalysis())
		assert.Equal(t, int64(15), configs.GetMonitorRetryInSeconds())
		assert.Equal(t, uuid.Nil.String(), configs.GetRepositoryAuthorization())
		assert.Equal(t, "text", configs.GetPrintOutputType())
		assert.Equal(t, "", configs.GetJSONOutputFilePath())
		assert.Equal(t, 0, len(configs.GetSeveritiesToIgnore()))
		assert.Equal(t, 0, len(configs.GetFilesOrPathsToIgnore()))
		assert.Equal(t, false, configs.GetReturnErrorIfFoundVulnerability())
		assert.Equal(t, currentPath, configs.GetProjectPath())
		assert.Equal(t, "", configs.GetFilterPath())
		assert.Equal(t, Config{}.workDir, configs.GetWorkDir())
		assert.Equal(t, false, configs.GetEnableGitHistoryAnalysis())
		assert.Equal(t, false, configs.GetCertInsecureSkipVerify())
		assert.Equal(t, "", configs.GetCertPath())
		assert.Equal(t, false, configs.GetEnableCommitAuthor())
		assert.Equal(t, "", configs.GetRepositoryName())
		assert.Equal(t, 0, len(configs.GetRiskAcceptHashes()))
		assert.Equal(t, 0, len(configs.GetFalsePositiveHashes()))
		assert.Equal(t, 0, len(configs.GetToolsToIgnore()))
		assert.Equal(t, 0, len(configs.GetHeaders()))
		assert.Equal(t, "", configs.GetContainerBindProjectPath())
		assert.Equal(t, true, configs.IsEmptyRepositoryAuthorization())
	})
	t.Run("Should change horusec config and return your new values", func(t *testing.T) {
		currentPath, _ := os.Getwd()
		configs := &Config{}
		configs.SetConfigFilePath(currentPath)
		configs.SetHorusecAPIURI(uuid.New().String())
		configs.SetTimeoutInSecondsRequest(1010)
		configs.SetTimeoutInSecondsAnalysis(1010)
		configs.SetMonitorRetryInSeconds(1010)
		configs.SetRepositoryAuthorization(uuid.New().String())
		configs.SetPrintOutputType("json")
		configs.SetJSONOutputFilePath("./other-file-path.json")
		configs.SetSeveritiesToIgnore([]string{"info"})
		configs.SetFilesOrPathsToIgnore([]string{"**/*_test.go"})
		configs.SetReturnErrorIfFoundVulnerability(true)
		configs.SetProjectPath("./some-other-file-path")
		configs.SetFilterPath("./run-this-path")
		configs.SetWorkDir(map[string]interface{}{"netcore": []interface{}{"test"}})
		configs.SetEnableGitHistoryAnalysis(true)
		configs.SetCertInsecureSkipVerify(true)
		configs.SetCertPath("./certs")
		configs.SetEnableCommitAuthor(true)
		configs.SetRepositoryName("my-project")
		configs.SetRiskAcceptHashes([]string{"123456789"})
		configs.SetFalsePositiveHashes([]string{"987654321"})
		configs.SetToolsToIgnore([]string{"horusecLeaks"})
		configs.SetHeaders(map[string]string{"x-header": "value"})
		configs.SetContainerBindProjectPath("./some-other-file-path")
		configs.SetIsTimeout(true)
		assert.NotEqual(t, "", configs.GetConfigFilePath())
		assert.NotEqual(t, "http://0.0.0.0:8000", configs.GetHorusecAPIUri())
		assert.NotEqual(t, int64(300), configs.GetTimeoutInSecondsRequest())
		assert.NotEqual(t, int64(600), configs.GetTimeoutInSecondsAnalysis())
		assert.NotEqual(t, int64(15), configs.GetMonitorRetryInSeconds())
		assert.NotEqual(t, uuid.Nil.String(), configs.GetRepositoryAuthorization())
		assert.NotEqual(t, "text", configs.GetPrintOutputType())
		assert.NotEqual(t, "", configs.GetJSONOutputFilePath())
		assert.NotEqual(t, 0, len(configs.GetSeveritiesToIgnore()))
		assert.NotEqual(t, 0, len(configs.GetFilesOrPathsToIgnore()))
		assert.NotEqual(t, false, configs.GetReturnErrorIfFoundVulnerability())
		assert.NotEqual(t, currentPath, configs.GetProjectPath())
		assert.NotEqual(t, "", configs.GetFilterPath())
		assert.NotEqual(t, Config{}.workDir, configs.GetWorkDir())
		assert.NotEqual(t, false, configs.GetEnableGitHistoryAnalysis())
		assert.NotEqual(t, false, configs.GetCertInsecureSkipVerify())
		assert.NotEqual(t, "", configs.GetCertPath())
		assert.NotEqual(t, false, configs.GetEnableCommitAuthor())
		assert.NotEqual(t, "", configs.GetRepositoryName())
		assert.NotEqual(t, 0, len(configs.GetRiskAcceptHashes()))
		assert.NotEqual(t, 0, len(configs.GetFalsePositiveHashes()))
		assert.NotEqual(t, 0, len(configs.GetToolsToIgnore()))
		assert.NotEqual(t, 0, len(configs.GetHeaders()))
		assert.NotEqual(t, "", configs.GetContainerBindProjectPath())
		assert.NotEqual(t, false, configs.GetIsTimeout())
	})
	t.Run("Should return horusec config using old viper file", func(t *testing.T) {
		viper.Reset()
		path, err := os.Getwd()
		assert.NoError(t, err)
		configs := &Config{}
		configs.SetConfigFilePath(path + "/.example-horusec-cli")
		viper.AddConfigPath(path)
		viper.SetConfigType("json")
		viper.SetConfigName(".example-horusec-cli")
		assert.NoError(t, viper.ReadInConfig())
		configs.NewConfigsFromViper()
		assert.Equal(t, path+"/.example-horusec-cli", configs.GetConfigFilePath())
		assert.Equal(t, "http://old-viper.horusec.com", configs.GetHorusecAPIUri())
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
		assert.Equal(t, "./tmp", configs.GetFilterPath())
		assert.Equal(t, &workdir.WorkDir{}, configs.GetWorkDir())
		assert.Equal(t, true, configs.GetEnableGitHistoryAnalysis())
		assert.Equal(t, true, configs.GetCertInsecureSkipVerify())
		assert.Equal(t, "", configs.GetCertPath())
		assert.Equal(t, true, configs.GetEnableCommitAuthor())
		assert.Equal(t, "horus", configs.GetRepositoryName())
		assert.Equal(t, []string{"hash3", "hash4"}, configs.GetRiskAcceptHashes())
		assert.Equal(t, []string{"hash1", "hash2"}, configs.GetFalsePositiveHashes())
		assert.Equal(t, []string{"GoSec"}, configs.GetToolsToIgnore())
		assert.Equal(t, map[string]string{"x-headers": "some-other-value"}, configs.GetHeaders())
		assert.Equal(t, "test", configs.GetContainerBindProjectPath())
	})
	t.Run("Should return horusec config using new viper file", func(t *testing.T) {
		viper.Reset()
		path, err := os.Getwd()
		assert.NoError(t, err)
		configs := &Config{}
		configs.SetConfigFilePath(path + "/.example-horusec-cli-new")
		viper.AddConfigPath(path)
		viper.SetConfigType("json")
		viper.SetConfigName(".example-horusec-cli-new")
		assert.NoError(t, viper.ReadInConfig())
		configs.NewConfigsFromViper()
		assert.Equal(t, path+"/.example-horusec-cli-new", configs.GetConfigFilePath())
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
		assert.Equal(t, "./tmp", configs.GetFilterPath())
		assert.Equal(t, &workdir.WorkDir{}, configs.GetWorkDir())
		assert.Equal(t, true, configs.GetEnableGitHistoryAnalysis())
		assert.Equal(t, true, configs.GetCertInsecureSkipVerify())
		assert.Equal(t, "", configs.GetCertPath())
		assert.Equal(t, true, configs.GetEnableCommitAuthor())
		assert.Equal(t, "horus", configs.GetRepositoryName())
		assert.Equal(t, []string{"hash3", "hash4"}, configs.GetRiskAcceptHashes())
		assert.Equal(t, []string{"hash1", "hash2"}, configs.GetFalsePositiveHashes())
		assert.Equal(t, []string{"GoSec"}, configs.GetToolsToIgnore())
		assert.Equal(t, map[string]string{"x-headers": "some-other-value"}, configs.GetHeaders())
		assert.Equal(t, "test", configs.GetContainerBindProjectPath())
	})
	t.Run("Should return horusec config using viper file and override by environment", func(t *testing.T) {
		viper.Reset()
		authorization := uuid.New().String()
		path, err := os.Getwd()
		assert.NoError(t, err)
		configs := &Config{}
		configs.SetConfigFilePath(path + "/.example-horusec-cli-new")
		viper.AddConfigPath(path)
		viper.SetConfigType("json")
		viper.SetConfigName(".example-horusec-cli-new")
		assert.NoError(t, viper.ReadInConfig())
		configs.NewConfigsFromViper()
		assert.NoError(t, os.Setenv(EnvHorusecAPIUri, "http://horusec.com"))
		assert.NoError(t, os.Setenv(EnvTimeoutInSecondsRequest, "99"))
		assert.NoError(t, os.Setenv(EnvTimeoutInSecondsAnalysis, "999"))
		assert.NoError(t, os.Setenv(EnvMonitorRetryInSeconds, "20"))
		assert.NoError(t, os.Setenv(EnvRepositoryAuthorization, authorization))
		assert.NoError(t, os.Setenv(EnvPrintOutputType, "sonarqube"))
		assert.NoError(t, os.Setenv(EnvJSONOutputFilePath, "./output-sonarqube.json"))
		assert.NoError(t, os.Setenv(EnvSeveritiesToIgnore, "AUDIT"))
		assert.NoError(t, os.Setenv(EnvFilesOrPathsToIgnore, "**/*_test.go, **/*_mock.go"))
		assert.NoError(t, os.Setenv(EnvReturnErrorIfFoundVulnerability, "false"))
		assert.NoError(t, os.Setenv(EnvProjectPath, "./horusec-manager"))
		assert.NoError(t, os.Setenv(EnvFilterPath, "src"))
		assert.NoError(t, os.Setenv(EnvEnableGitHistoryAnalysis, "false"))
		assert.NoError(t, os.Setenv(EnvCertInsecureSkipVerify, "false"))
		assert.NoError(t, os.Setenv(EnvCertPath, "./"))
		assert.NoError(t, os.Setenv(EnvEnableCommitAuthor, "false"))
		assert.NoError(t, os.Setenv(EnvRepositoryName, "my-project"))
		assert.NoError(t, os.Setenv(EnvFalsePositiveHashes, "hash9, hash8"))
		assert.NoError(t, os.Setenv(EnvRiskAcceptHashes, "hash7, hash6"))
		assert.NoError(t, os.Setenv(EnvToolsToIgnore, "TfSec"))
		assert.NoError(t, os.Setenv(EnvHeaders, "{\"x-auth\": \"987654321\"}"))
		assert.NoError(t, os.Setenv(EnvContainerBindProjectPath, "./my-path"))
		configs.NewConfigsFromEnvironments()
		assert.Equal(t, path+"/.example-horusec-cli-new", configs.GetConfigFilePath())
		assert.Equal(t, "http://horusec.com", configs.GetHorusecAPIUri())
		assert.Equal(t, int64(99), configs.GetTimeoutInSecondsRequest())
		assert.Equal(t, int64(999), configs.GetTimeoutInSecondsAnalysis())
		assert.Equal(t, int64(20), configs.GetMonitorRetryInSeconds())
		assert.Equal(t, authorization, configs.GetRepositoryAuthorization())
		assert.Equal(t, "sonarqube", configs.GetPrintOutputType())
		assert.Equal(t, "./output-sonarqube.json", configs.GetJSONOutputFilePath())
		assert.Equal(t, []string{"AUDIT"}, configs.GetSeveritiesToIgnore())
		assert.Equal(t, []string{"**/*_test.go", "**/*_mock.go"}, configs.GetFilesOrPathsToIgnore())
		assert.Equal(t, false, configs.GetReturnErrorIfFoundVulnerability())
		assert.Equal(t, "./horusec-manager", configs.GetProjectPath())
		assert.Equal(t, "src", configs.GetFilterPath())
		assert.Equal(t, &workdir.WorkDir{}, configs.GetWorkDir())
		assert.Equal(t, false, configs.GetEnableGitHistoryAnalysis())
		assert.Equal(t, false, configs.GetCertInsecureSkipVerify())
		assert.Equal(t, "./", configs.GetCertPath())
		assert.Equal(t, false, configs.GetEnableCommitAuthor())
		assert.Equal(t, "my-project", configs.GetRepositoryName())
		assert.Equal(t, []string{"hash7", "hash6"}, configs.GetRiskAcceptHashes())
		assert.Equal(t, []string{"hash9", "hash8"}, configs.GetFalsePositiveHashes())
		assert.Equal(t, []string{"TfSec"}, configs.GetToolsToIgnore())
		assert.Equal(t, map[string]string{"x-auth": "987654321"}, configs.GetHeaders())
		assert.Equal(t, "./my-path", configs.GetContainerBindProjectPath())
	})
	t.Run("Should return horusec config using viper file and override by environment and override by flags", func(t *testing.T) {
		viper.Reset()
		authorization := uuid.New().String()
		path, err := os.Getwd()
		assert.NoError(t, err)
		configs := &Config{}
		configs.factoryParseInputToSliceString(map[string]interface{}{})
		configs.SetConfigFilePath(path + "/.example-horusec-cli-new")
		viper.AddConfigPath(path)
		viper.SetConfigType("json")
		viper.SetConfigName(".example-horusec-cli-new")
		assert.NoError(t, viper.ReadInConfig())
		configs.NewConfigsFromViper()
		assert.NoError(t, os.Setenv(EnvHorusecAPIUri, "http://horusec.com"))
		assert.NoError(t, os.Setenv(EnvTimeoutInSecondsRequest, "99"))
		assert.NoError(t, os.Setenv(EnvTimeoutInSecondsAnalysis, "999"))
		assert.NoError(t, os.Setenv(EnvMonitorRetryInSeconds, "20"))
		assert.NoError(t, os.Setenv(EnvRepositoryAuthorization, authorization))
		assert.NoError(t, os.Setenv(EnvPrintOutputType, "sonarqube"))
		assert.NoError(t, os.Setenv(EnvJSONOutputFilePath, "./output-sonarqube.json"))
		assert.NoError(t, os.Setenv(EnvSeveritiesToIgnore, "AUDIT"))
		assert.NoError(t, os.Setenv(EnvFilesOrPathsToIgnore, "**/*_test.go, **/*_mock.go"))
		assert.NoError(t, os.Setenv(EnvReturnErrorIfFoundVulnerability, "false"))
		assert.NoError(t, os.Setenv(EnvProjectPath, "./horusec-manager"))
		assert.NoError(t, os.Setenv(EnvFilterPath, "src"))
		assert.NoError(t, os.Setenv(EnvEnableGitHistoryAnalysis, "false"))
		assert.NoError(t, os.Setenv(EnvCertInsecureSkipVerify, "false"))
		assert.NoError(t, os.Setenv(EnvCertPath, "./"))
		assert.NoError(t, os.Setenv(EnvEnableCommitAuthor, "false"))
		assert.NoError(t, os.Setenv(EnvRepositoryName, "my-project"))
		assert.NoError(t, os.Setenv(EnvFalsePositiveHashes, "hash9, hash8"))
		assert.NoError(t, os.Setenv(EnvRiskAcceptHashes, "hash7, hash6"))
		assert.NoError(t, os.Setenv(EnvToolsToIgnore, "TfSec"))
		assert.NoError(t, os.Setenv(EnvHeaders, "{\"x-auth\": \"987654321\"}"))
		assert.NoError(t, os.Setenv(EnvContainerBindProjectPath, "./my-path"))
		configs.NewConfigsFromEnvironments()
		assert.Equal(t, path+"/.example-horusec-cli-new", configs.GetConfigFilePath())
		assert.Equal(t, "http://horusec.com", configs.GetHorusecAPIUri())
		assert.Equal(t, int64(99), configs.GetTimeoutInSecondsRequest())
		assert.Equal(t, int64(999), configs.GetTimeoutInSecondsAnalysis())
		assert.Equal(t, int64(20), configs.GetMonitorRetryInSeconds())
		assert.Equal(t, authorization, configs.GetRepositoryAuthorization())
		assert.Equal(t, "sonarqube", configs.GetPrintOutputType())
		assert.Equal(t, "./output-sonarqube.json", configs.GetJSONOutputFilePath())
		assert.Equal(t, []string{"AUDIT"}, configs.GetSeveritiesToIgnore())
		assert.Equal(t, []string{"**/*_test.go", "**/*_mock.go"}, configs.GetFilesOrPathsToIgnore())
		assert.Equal(t, false, configs.GetReturnErrorIfFoundVulnerability())
		assert.Equal(t, "./horusec-manager", configs.GetProjectPath())
		assert.Equal(t, "src", configs.GetFilterPath())
		assert.Equal(t, &workdir.WorkDir{}, configs.GetWorkDir())
		assert.Equal(t, false, configs.GetEnableGitHistoryAnalysis())
		assert.Equal(t, false, configs.GetCertInsecureSkipVerify())
		assert.Equal(t, "./", configs.GetCertPath())
		assert.Equal(t, false, configs.GetEnableCommitAuthor())
		assert.Equal(t, "my-project", configs.GetRepositoryName())
		assert.Equal(t, []string{"hash7", "hash6"}, configs.GetRiskAcceptHashes())
		assert.Equal(t, []string{"hash9", "hash8"}, configs.GetFalsePositiveHashes())
		assert.Equal(t, []string{"TfSec"}, configs.GetToolsToIgnore())
		assert.Equal(t, map[string]string{"x-auth": "987654321"}, configs.GetHeaders())
		assert.Equal(t, "./my-path", configs.GetContainerBindProjectPath())
		cobraCmd := &cobra.Command{
			Use:     "start",
			Short:   "Start horusec-cli",
			Long:    "Start the Horusec' analysis in the current path",
			Example: "horusec start",
			RunE: func(cmd *cobra.Command, args []string) error {
				return nil
			},
		}
		configs.NewConfigsFromCobraAndLoadsFlags(cobraCmd)
		cobraCmd.SetArgs([]string{"-p", "/home/usr/project", "-F", "SOMEHASHALEATORY1,SOMEHASHALEATORY2", "-R", "SOMEHASHALEATORY3,SOMEHASHALEATORY4"})
		assert.NoError(t, cobraCmd.Execute())
		assert.Equal(t, "/home/usr/project", configs.GetProjectPath())
		assert.Equal(t, []string{"SOMEHASHALEATORY1", "SOMEHASHALEATORY2"}, configs.GetFalsePositiveHashes())
		assert.Equal(t, []string{"SOMEHASHALEATORY3", "SOMEHASHALEATORY4"}, configs.GetRiskAcceptHashes())
	})
}

func TestToLowerCamel(t *testing.T) {
	t.Run("should success set all configs as lower camel case", func(t *testing.T) {
		configs := &Config{}

		assert.Equal(t, "horusecCliHorusecApiUri", configs.toLowerCamel(EnvHorusecAPIUri))
		assert.Equal(t, "horusecCliTimeoutInSecondsRequest", configs.toLowerCamel(EnvTimeoutInSecondsRequest))
		assert.Equal(t, "horusecCliTimeoutInSecondsAnalysis", configs.toLowerCamel(EnvTimeoutInSecondsAnalysis))
		assert.Equal(t, "horusecCliMonitorRetryInSeconds", configs.toLowerCamel(EnvMonitorRetryInSeconds))
		assert.Equal(t, "horusecCliRepositoryAuthorization", configs.toLowerCamel(EnvRepositoryAuthorization))
		assert.Equal(t, "horusecCliPrintOutputType", configs.toLowerCamel(EnvPrintOutputType))
		assert.Equal(t, "horusecCliJsonOutputFilepath", configs.toLowerCamel(EnvJSONOutputFilePath))
		assert.Equal(t, "horusecCliSeveritiesToIgnore", configs.toLowerCamel(EnvSeveritiesToIgnore))
		assert.Equal(t, "horusecCliFilesOrPathsToIgnore", configs.toLowerCamel(EnvFilesOrPathsToIgnore))
		assert.Equal(t, "horusecCliReturnErrorIfFoundVulnerability", configs.toLowerCamel(EnvReturnErrorIfFoundVulnerability))
		assert.Equal(t, "horusecCliProjectPath", configs.toLowerCamel(EnvProjectPath))
		assert.Equal(t, "horusecCliWorkDir", configs.toLowerCamel(EnvWorkDirPath))
		assert.Equal(t, "horusecCliFilterPath", configs.toLowerCamel(EnvFilterPath))
		assert.Equal(t, "horusecCliEnableGitHistoryAnalysis", configs.toLowerCamel(EnvEnableGitHistoryAnalysis))
		assert.Equal(t, "horusecCliEnableCommitAuthor", configs.toLowerCamel(EnvEnableCommitAuthor))
		assert.Equal(t, "horusecCliCertInsecureSkipVerify", configs.toLowerCamel(EnvCertInsecureSkipVerify))
		assert.Equal(t, "horusecCliRepositoryName", configs.toLowerCamel(EnvRepositoryName))
		assert.Equal(t, "horusecCliFalsePositiveHashes", configs.toLowerCamel(EnvFalsePositiveHashes))
		assert.Equal(t, "horusecCliRiskAcceptHashes", configs.toLowerCamel(EnvRiskAcceptHashes))
		assert.Equal(t, "horusecCliToolsToIgnore", configs.toLowerCamel(EnvToolsToIgnore))
		assert.Equal(t, "horusecCliHeaders", configs.toLowerCamel(EnvHeaders))
		assert.Equal(t, "horusecCliContainerBindProjectPath", configs.toLowerCamel(EnvContainerBindProjectPath))
	})
}

func TestNormalizeConfigs(t *testing.T) {
	t.Run("Should success normalize config", func(t *testing.T) {
		config := &Config{}
		config.SetJSONOutputFilePath("./cli")
		config.SetProjectPath("./cli")

		assert.NotEmpty(t, config.NormalizeConfigs())
	})
}

func TestConfig_ToBytes(t *testing.T) {
	t.Run("Should success when parse config to json bytes without indent", func(t *testing.T) {
		config := &Config{}
		config.NewConfigsFromEnvironments()
		assert.NotEmpty(t, config.ToBytes(false))
	})
	t.Run("Should success when parse config to json bytes with indent", func(t *testing.T) {
		config := &Config{}
		config.NewConfigsFromEnvironments()
		assert.NotEmpty(t, config.ToBytes(true))
	})
}

func TestConfigMock(t *testing.T) {
	m := &Mock{}
	m.On("SetConfigFilePath")
	m.On("GetConfigFilePath").Return(".")
	m.On("SetHorusecAPIURI")
	m.On("GetHorusecAPIUri").Return(".")
	m.On("SetTimeoutInSecondsRequest")
	m.On("GetTimeoutInSecondsRequest").Return(int64(10))
	m.On("SetTimeoutInSecondsAnalysis")
	m.On("GetTimeoutInSecondsAnalysis").Return(int64(10))
	m.On("SetMonitorRetryInSeconds")
	m.On("GetMonitorRetryInSeconds").Return(int64(10))
	m.On("SetRepositoryAuthorization")
	m.On("GetRepositoryAuthorization").Return(".")
	m.On("SetPrintOutputType")
	m.On("GetPrintOutputType").Return(".")
	m.On("SetJSONOutputFilePath")
	m.On("GetJSONOutputFilePath").Return(".")
	m.On("SetSeveritiesToIgnore")
	m.On("GetSeveritiesToIgnore").Return([]string{"."})
	m.On("SetFilesOrPathsToIgnore")
	m.On("GetFilesOrPathsToIgnore").Return([]string{"."})
	m.On("SetReturnErrorIfFoundVulnerability")
	m.On("GetReturnErrorIfFoundVulnerability").Return(true)
	m.On("SetProjectPath")
	m.On("GetFilterPath").Return(".")
	m.On("SetEnableGitHistoryAnalysis")
	m.On("GetEnableGitHistoryAnalysis").Return(true)
	m.On("SetCertInsecureSkipVerify")
	m.On("GetCertInsecureSkipVerify").Return(true)
	m.On("SetCertPath")
	m.On("GetCertPath").Return(".")
	m.On("SetWorkDir")
	m.On("GetWorkDir").Return(&workdir.WorkDir{
		CSharp: []string{"./"},
	})
	m.On("SetFilterPath")
	m.On("GetProjectPath").Return(".")
	m.On("SetEnableCommitAuthor")
	m.On("GetEnableCommitAuthor").Return(true)
	m.On("SetRepositoryName")
	m.On("GetRepositoryName").Return(".")
	m.On("SetRiskAcceptHashes")
	m.On("GetRiskAcceptHashes").Return([]string{"."})
	m.On("SetFalsePositiveHashes")
	m.On("GetFalsePositiveHashes").Return([]string{"."})
	m.On("SetToolsToIgnore")
	m.On("GetToolsToIgnore").Return([]string{"."})
	m.On("SetHeaders")
	m.On("GetHeaders").Return(map[string]string{"x": "x"})
	m.On("SetContainerBindProjectPath")
	m.On("GetContainerBindProjectPath").Return(".")
	m.On("SetIsTimeout")
	m.On("GetIsTimeout").Return(true)
	m.On("IsEmptyRepositoryAuthorization").Return(true)
	m.On("ToBytes").Return([]byte("{}"))
	m.On("NormalizeConfigs").Return(&Config{projectPath: "./"})
	m.On("NewConfigsFromEnvironments").Return(&Config{})
	m.On("NewConfigsFromEnvironments").Return(&Config{})
	m.On("NewConfigsFromCobraAndLoadsFlags").Return(&Config{})
	m.SetConfigFilePath(".")
	assert.NotEmpty(t, m.GetConfigFilePath())
	m.SetHorusecAPIURI(".")
	assert.NotEmpty(t, m.GetHorusecAPIUri())
	m.SetTimeoutInSecondsRequest(10)
	assert.NotEmpty(t, m.GetTimeoutInSecondsRequest())
	m.SetTimeoutInSecondsAnalysis(10)
	assert.NotEmpty(t, m.GetTimeoutInSecondsAnalysis())
	m.SetMonitorRetryInSeconds(10)
	assert.NotEmpty(t, m.GetMonitorRetryInSeconds())
	m.SetRepositoryAuthorization(".")
	assert.NotEmpty(t, m.GetRepositoryAuthorization())
	m.SetPrintOutputType(".")
	assert.NotEmpty(t, m.GetPrintOutputType())
	m.SetJSONOutputFilePath(".")
	assert.NotEmpty(t, m.GetJSONOutputFilePath())
	m.SetSeveritiesToIgnore([]string{"."})
	assert.NotEmpty(t, m.GetSeveritiesToIgnore())
	m.SetFilesOrPathsToIgnore([]string{"."})
	assert.NotEmpty(t, m.GetFilesOrPathsToIgnore())
	m.SetReturnErrorIfFoundVulnerability(true)
	assert.NotEmpty(t, m.GetReturnErrorIfFoundVulnerability())
	m.SetProjectPath(".")
	assert.NotEmpty(t, m.GetProjectPath())
	m.SetFilterPath(".")
	assert.NotEmpty(t, m.GetFilterPath())
	m.SetWorkDir("{}")
	assert.NotEmpty(t, m.GetWorkDir())
	m.SetEnableGitHistoryAnalysis(true)
	assert.NotEmpty(t, m.GetEnableGitHistoryAnalysis())
	m.SetCertInsecureSkipVerify(true)
	assert.NotEmpty(t, m.GetCertInsecureSkipVerify())
	m.SetCertPath(".")
	assert.NotEmpty(t, m.GetCertPath())
	m.SetEnableCommitAuthor(true)
	assert.NotEmpty(t, m.GetEnableCommitAuthor())
	m.SetRepositoryName(".")
	assert.NotEmpty(t, m.GetRepositoryName())
	m.SetRiskAcceptHashes([]string{"."})
	assert.NotEmpty(t, m.GetRiskAcceptHashes())
	m.SetFalsePositiveHashes([]string{"."})
	assert.NotEmpty(t, m.GetFalsePositiveHashes())
	m.SetToolsToIgnore([]string{"."})
	assert.NotEmpty(t, m.GetToolsToIgnore())
	m.SetHeaders(".")
	assert.NotEmpty(t, m.GetHeaders())
	m.SetContainerBindProjectPath(".")
	assert.NotEmpty(t, m.GetContainerBindProjectPath())
	m.SetIsTimeout(true)
	assert.NotEmpty(t, m.GetIsTimeout())
	assert.NotEmpty(t, m.IsEmptyRepositoryAuthorization())
	assert.NotEmpty(t, m.ToBytes(true))
	assert.NotEmpty(t, m.NormalizeConfigs())
	m.NewConfigsFromEnvironments()
	m.NewConfigsFromEnvironments()
	m.NewConfigsFromCobraAndLoadsFlags(&cobra.Command{})
}
