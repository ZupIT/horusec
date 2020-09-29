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
	"os"
	"testing"

	"github.com/ZupIT/horusec/horusec-cli/internal/entities/workdir"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestNewHorusecConfig(t *testing.T) {
	wd := &workdir.WorkDir{}
	t.Run("Should return horusec config with your default values", func(t *testing.T) {
		configs := &Config{}
		configs.SetConfigsFromEnvironments()
		assert.Equal(t, configs.HorusecAPIUri, "http://0.0.0.0:8000")
		assert.Equal(t, configs.TimeoutInSecondsRequest, int64(300))
		assert.Equal(t, configs.TimeoutInSecondsAnalysis, int64(600))
		assert.Equal(t, configs.MonitorRetryInSeconds, int64(15))
		assert.Equal(t, configs.RepositoryAuthorization, uuid.Nil.String())
		assert.Equal(t, configs.PrintOutputType, "text")
		assert.Equal(t, configs.JSONOutputFilePath, "")
		assert.Equal(t, configs.TypesOfVulnerabilitiesToIgnore, "")
		assert.Equal(t, configs.FilesOrPathsToIgnore, "")
		assert.Equal(t, configs.CertPath, "")
		assert.Equal(t, configs.CertInsecureSkipVerify, false)
		assert.Equal(t, configs.ReturnErrorIfFoundVulnerability, false)
		path, _ := os.Getwd()
		assert.Equal(t, configs.ProjectPath, path)
		assert.Equal(t, configs.WorkDir, Config{}.WorkDir)
		assert.Equal(t, configs.FilterPath, "")
		assert.Equal(t, configs.EnableGitHistoryAnalysis, false)
		assert.Equal(t, configs.CertInsecureSkipVerify, false)
		assert.Equal(t, configs.RepositoryName, "")
	})
	t.Run("Should change horusec config and return your new values", func(t *testing.T) {
		configs := &Config{}
		configs.SetHorusecAPIURI(uuid.New().String())
		configs.SetTimeoutInSecondsRequest(1010)
		configs.SetTimeoutInSecondsAnalysis(1010)
		configs.SetMonitorRetryInSeconds(1010)
		configs.SetRepositoryAuthorization(uuid.New().String())
		configs.SetPrintOutputType(uuid.New().String())
		configs.SetJSONOutputFilePath(uuid.New().String())
		configs.SetTypesOfVulnerabilitiesToIgnore(uuid.New().String())
		configs.SetFilesOrPathsToIgnore(uuid.New().String())
		configs.SetReturnErrorIfFoundVulnerability(true)
		configs.SetProjectPath(uuid.New().String())
		configs.SetFilterPath(uuid.New().String())
		configs.SetEnableGitHistoryAnalysis(true)
		configs.SetProjectPath("./")
		configs.SetWorkDir(wd.String())
		configs.SetCertPath("./")
		configs.SetCertInsecureSkipVerify(true)
		configs.SetRepositoryName("horus")
		assert.NotEqual(t, configs.GetHorusecAPIUri(), "http://0.0.0.0:8000")
		assert.NotEqual(t, configs.GetTimeoutInSecondsRequest(), int64(300))
		assert.NotEqual(t, configs.GetTimeoutInSecondsAnalysis(), int64(600))
		assert.NotEqual(t, configs.GetMonitorRetryInSeconds(), int64(15))
		assert.NotEqual(t, configs.GetRepositoryAuthorization(), "")
		assert.NotEqual(t, configs.GetPrintOutputType(), "text")
		assert.NotEqual(t, configs.GetJSONOutputFilePath(), "")
		assert.NotEqual(t, configs.GetTypesOfVulnerabilitiesToIgnore(), "")
		assert.NotEqual(t, configs.GetFilesOrPathsToIgnore(), "")
		assert.NotEqual(t, configs.GetCertPath(), "")
		assert.NotEqual(t, configs.GetCertInsecureSkipVerify(), false)
		assert.NotEqual(t, configs.GetReturnErrorIfFoundVulnerability(), false)
		assert.NotEqual(t, configs.GetProjectPath(), "")
		assert.NotEqual(t, configs.GetFilterPath(), "")
		assert.NotEqual(t, configs.GetEnableGitHistoryAnalysis(), false)
		assert.NotEqual(t, configs.GetCertInsecureSkipVerify(), false)
		assert.NotEqual(t, configs.GetRepositoryName(), "")
	})
	t.Run("Should return horusec config using viper file", func(t *testing.T) {
		path, err := os.Getwd()
		configs := &Config{}
		configs.ConfigFilePath = path + "/.example-horusec-cli"
		assert.NoError(t, err)
		viper.AddConfigPath(path)
		viper.SetConfigType("json")
		viper.SetConfigName(".example-horusec-cli")
		assert.NoError(t, viper.ReadInConfig())
		configs.SetConfigsFromViper()
		assert.Equal(t, "http://dev.horusec.com", configs.HorusecAPIUri)
		assert.Equal(t, int64(20), configs.TimeoutInSecondsRequest)
		assert.Equal(t, int64(100), configs.TimeoutInSecondsAnalysis)
		assert.Equal(t, int64(10), configs.MonitorRetryInSeconds)
		assert.Equal(t, "8beffdca-636e-4d73-a22f-b0f7c3cff1c4", configs.RepositoryAuthorization)
		assert.Equal(t, "json", configs.PrintOutputType)
		assert.Equal(t, "./output.json", configs.JSONOutputFilePath)
		assert.Equal(t, "NOSEC", configs.TypesOfVulnerabilitiesToIgnore)
		assert.Equal(t, "./assets", configs.FilesOrPathsToIgnore)
		assert.Equal(t, true, configs.ReturnErrorIfFoundVulnerability)
		assert.Equal(t, "./", configs.ProjectPath)
		assert.Equal(t, wd, configs.WorkDir)
		assert.Equal(t, configs.FilterPath, "./tmp")
		assert.Equal(t, configs.EnableGitHistoryAnalysis, true)
		assert.Equal(t, configs.CertInsecureSkipVerify, true)
		assert.Equal(t, configs.RepositoryName, "horus")
	})
	t.Run("Should return horusec config using viper file and override by environment", func(t *testing.T) {
		authorization := uuid.New().String()
		path, err := os.Getwd()
		configs := &Config{}
		configs.ConfigFilePath = path + "/.example-horusec-cli"
		assert.NoError(t, err)
		viper.AddConfigPath(path)
		viper.SetConfigType("json")
		viper.SetConfigName(".example-horusec-cli")
		assert.NoError(t, viper.ReadInConfig())
		configs.SetConfigsFromViper()
		assert.NoError(t, os.Setenv(EnvHorusecAPIUri, "http://horusec.com"))
		assert.NoError(t, os.Setenv(EnvTimeoutInSecondsRequest, "50"))
		assert.NoError(t, os.Setenv(EnvTimeoutInSecondsAnalysis, "150"))
		assert.NoError(t, os.Setenv(EnvMonitorRetryInSeconds, "30"))
		assert.NoError(t, os.Setenv(EnvRepositoryAuthorization, authorization))
		assert.NoError(t, os.Setenv(EnvPrintOutputType, "sonarqube"))
		assert.NoError(t, os.Setenv(EnvJSONOutputFilePath, "./sonar.json"))
		assert.NoError(t, os.Setenv(EnvTypesOfVulnerabilitiesToIgnore, "AUDIT"))
		assert.NoError(t, os.Setenv(EnvFilesOrPathsToIgnore, "./deployments"))
		assert.NoError(t, os.Setenv(EnvReturnErrorIfFoundVulnerability, "false"))
		assert.NoError(t, os.Setenv(EnvProjectPath, "./horusec-manager"))
		assert.NoError(t, os.Setenv(EnvFilterPath, "src"))
		assert.NoError(t, os.Setenv(EnvEnableGitHistoryAnalysis, "true"))
		assert.NoError(t, os.Setenv(EnvCertInsecureSkipVerify, "true"))
		assert.NoError(t, os.Setenv(EnvRepositoryName, "horus"))
		configs.SetConfigsFromEnvironments()
		assert.Equal(t, "http://horusec.com", configs.HorusecAPIUri)
		assert.Equal(t, int64(50), configs.TimeoutInSecondsRequest)
		assert.Equal(t, int64(150), configs.TimeoutInSecondsAnalysis)
		assert.Equal(t, int64(30), configs.MonitorRetryInSeconds)
		assert.Equal(t, authorization, configs.RepositoryAuthorization)
		assert.Equal(t, "sonarqube", configs.PrintOutputType)
		assert.Equal(t, "./sonar.json", configs.JSONOutputFilePath)
		assert.Equal(t, "AUDIT", configs.TypesOfVulnerabilitiesToIgnore)
		assert.Equal(t, "./deployments", configs.FilesOrPathsToIgnore)
		assert.Equal(t, false, configs.ReturnErrorIfFoundVulnerability)
		assert.Equal(t, "./horusec-manager", configs.ProjectPath)
		assert.Equal(t, wd, configs.WorkDir)
		assert.Equal(t, "src", configs.FilterPath)
		assert.Equal(t, true, configs.EnableGitHistoryAnalysis)
		assert.Equal(t, true, configs.CertInsecureSkipVerify)
		assert.Equal(t, "horus", configs.RepositoryName)
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
		assert.Equal(t, "horusecCliTypesOfVulnerabilitiesToIgnore", configs.toLowerCamel(EnvTypesOfVulnerabilitiesToIgnore))
		assert.Equal(t, "horusecCliFilesOrPathsToIgnore", configs.toLowerCamel(EnvFilesOrPathsToIgnore))
		assert.Equal(t, "horusecCliReturnErrorIfFoundVulnerability", configs.toLowerCamel(EnvReturnErrorIfFoundVulnerability))
		assert.Equal(t, "horusecCliProjectPath", configs.toLowerCamel(EnvProjectPath))
		assert.Equal(t, "horusecCliWorkDir", configs.toLowerCamel(EnvWorkDirPath))
		assert.Equal(t, "horusecCliFilterPath", configs.toLowerCamel(EnvFilterPath))
		assert.Equal(t, "horusecCliEnableGitHistoryAnalysis", configs.toLowerCamel(EnvEnableGitHistoryAnalysis))
		assert.Equal(t, "horusecCliCertInsecureSkipVerify", configs.toLowerCamel(EnvCertInsecureSkipVerify))
		assert.Equal(t, "horusecCliRepositoryName", configs.toLowerCamel(EnvRepositoryName))
	})
}
