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
	"encoding/json"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"os"
	"strings"

	"github.com/iancoleman/strcase"

	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/text"
	"github.com/ZupIT/horusec/horusec-cli/internal/entities/workdir"
	"github.com/google/uuid"
	"github.com/spf13/viper"
)

const (
	// This setting has the purpose of identifying where the url where the horusec-api service is hosted will be
	// By default is http://0.0.0.0:8000
	// Validation: It is mandatory to be a valid url
	EnvHorusecAPIUri = "HORUSEC_CLI_HORUSEC_API_URI"
	// This setting will identify how long I want to wait in seconds to send the analysis object to horusec-api
	// By default is 300
	// Validation: It is mandatory to be greater than 10
	EnvTimeoutInSecondsRequest = "HORUSEC_CLI_TIMEOUT_IN_SECONDS_REQUEST"
	// This setting will identify how long I want to wait in seconds to carry out an analysis that includes:
	// acquiring a project, sending it to analysis containers and acquiring a response
	// By default is 600
	// Validation: It is mandatory to be greater than 10
	EnvTimeoutInSecondsAnalysis = "HORUSEC_CLI_TIMEOUT_IN_SECONDS_ANALYSIS"
	// This setting will identify how many in how many seconds
	// I want to check if my analysis is close to the timeout
	// By default is 15
	// Validation: It is mandatory to be greater than 10
	EnvMonitorRetryInSeconds = "HORUSEC_CLI_MONITOR_RETRY_IN_SECONDS"
	// This setting is to identify which repository you are analyzing from.
	// This repository is created within the horusec webapp
	// By default is 00000000-0000-0000-0000-000000000000
	// Validation: If exist It is mandatory to be valid uuid
	EnvRepositoryAuthorization = "HORUSEC_CLI_REPOSITORY_AUTHORIZATION"
	// This setting is to know what type of output you want for the analysis (text, json, sonarqube)
	// By default is text
	// Validation: It is mandatory to be in text, json, sonarqube
	EnvPrintOutputType = "HORUSEC_CLI_PRINT_OUTPUT_TYPE"
	// This setting is to know in which directory you want the output of the json file
	// generated by the output types json or sonarqube to be located.
	// By default if the type is json or sonarqube o path is ./output.json
	// Validation: It is mandatory to be valid path
	EnvJSONOutputFilePath = "HORUSEC_CLI_JSON_OUTPUT_FILEPATH"
	// This setting is to find out what types of severity I don't want you to recognize as a vulnerability.
	// The types are: "LOW", "MEDIUM", "HIGH", "NOSEC", "AUDIT"
	// If you want ignore other you can add in value. Ex.: "LOW, MEDIUM, NOSEC"
	// This setting is to know what types of severity
	// I do not want you to recognize as a vulnerability
	// and will not count towards the return of exit (1) if configured
	// Validation: It is mandatory to be in "LOW", "MEDIUM", "HIGH", "NOSEC", "AUDIT"
	EnvTypesOfVulnerabilitiesToIgnore = "HORUSEC_CLI_TYPES_OF_VULNERABILITIES_TO_IGNORE"
	// This setting is to know which files and folders I want to ignore to send for analysis
	// By default we ignore each other:
	//   * Folders: "/.horusec/", "/.idea/", "/.vscode/", "/tmp/", "/bin/", "/node_modules/", "/vendor/"
	//   * Files: ".jpg", ".png", ".gif", ".webp", ".tiff", ".psd", ".raw", ".bmp", ".heif", ".indd",
	//		".jpeg", ".svg", ".ai", ".eps", ".pdf", ".webm", ".mpg", ".mp2", ".mpeg", ".mpe",
	//		".mp4", ".m4p", ".m4v", ".avi", ".wmv", ".mov", ".qt", ".flv", ".swf", ".avchd", ".mpv", ".ogg",
	EnvFilesOrPathsToIgnore = "HORUSEC_CLI_FILES_OR_PATHS_TO_IGNORE"
	// This setting is to know if I want return exit(1) if I find any vulnerability in the analysis
	// By default is false
	// Validation: It is mandatory to be in "false", "true"
	EnvReturnErrorIfFoundVulnerability = "HORUSEC_CLI_RETURN_ERROR_IF_FOUND_VULNERABILITY"
	// This setting is to know if I want to change the analysis directory
	// and do not want to run in the current directory.
	// If this value is not passed, Horusec will ask if you want to run the analysis in the current directory.
	// If you pass it it will start the analysis in the directory informed by you without asking anything.
	// By default is CURRENT DIRECTORY
	// Validation: It is mandatory to be valid path
	EnvProjectPath = "HORUSEC_CLI_PROJECT_PATH"
	// This setting is to know in which directory I want to perform the analysis of each language.
	// As a key you must pass the name of the language and the value the directory from within your project.
	// Example:
	// Let's assume that your project is a netcore app using angular and has the following structure:
	// - NetCoreProject/
	//   - controllers/
	//   - NetCoreProject.csproj
	//   - views/
	//     - pages/
	//     - package.json
	//     - package-lock.json
	// Then your workdir would be:
	// {
	//   "netCore": "NetCoreProject",
	//   "javaScript": "NetCoreProject/views"
	// }
	// The interface is:
	// {
	//   go string
	//   netCore string
	//   ruby string
	//   python string
	//   java string
	//   kotlin string
	//   javaScript string
	//   git string
	//   generic string
	// }
	// Validation: It is mandatory to be valid interface of workdir to proceed
	EnvWorkDirPath = "HORUSEC_CLI_WORK_DIR"
	// This setting is to setup the path to run analysis keep current path in your base.
	// By default is empty
	// Validation: if exists is required valid path
	EnvFilterPath = "HORUSEC_CLI_FILTER_PATH"
	// This setting is to know if I want enable run gitleaks tools
	// and analysis in all git history searching vulnerabilities
	// By default is false
	// Validation: It is mandatory to be in "false", "true"
	EnvEnableGitHistoryAnalysis = "HORUSEC_CLI_ENABLE_GIT_HISTORY_ANALYSIS"
	// Used to authorize the sending of unsafe requests. Its use is not recommended outside testing scenarios.
	// By default is false
	// Validation: It is mandatory to be in "false", "true"
	EnvCertInsecureSkipVerify = "HORUSEC_CLI_CERT_INSECURE_SKIP_VERIFY"
	// Used to pass the path to a certificate that will be sent on the http request to the horusec server.
	// Example: /home/certs/ca.crt
	// Validation: It must be a valid path
	EnvCertPath = "HORUSEC_CLI_CERT_PATH"
	// Used to enable or disable search with vulnerability author.
	// By default is false
	// Validation: It is mandatory to be in "false", "true"
	EnvEnableCommitAuthor = "HORUSEC_CLI_ENABLE_COMMIT_AUTHOR"
	// Used to send the repository name to the server, must be used together with the company token.
	// By default is empty
	EnvRepositoryName = "HORUSEC_CLI_REPOSITORY_NAME"
	// Used to skip vulnerability of type false positive
	// By default is empty
	EnvFalsePositiveHashes = "HORUSEC_CLI_FALSE_POSITIVE_HASHES"
	// Used to skip vulnerability of type risk accept
	// By default is empty
	EnvRiskAcceptHashes = "HORUSEC_CLI_RISK_ACCEPT_HASHES"
	// Used to ignore tools for run
	// By default is empty
	EnvToolsToIgnore = "HORUSEC_CLI_TOOLS_TO_IGNORE"
	// Used send others headers on request to send in horusec-api
	// By default is empty
	EnvHeaders = "HORUSEC_CLI_HEADERS"
	// Used to pass project path in host when running horusec cli inside a container
	// By default is empty
	EnvContainerBindProjectPath = "HORUSEC_CLI_CONTAINER_BIND_PROJECT_PATH"
)

type Config struct {
	ConfigFilePath                  string
	HorusecAPIUri                   string
	TimeoutInSecondsRequest         int64
	IsTimeout                       bool
	TimeoutInSecondsAnalysis        int64
	MonitorRetryInSeconds           int64
	RepositoryAuthorization         string
	Headers                         string
	PrintOutputType                 string
	JSONOutputFilePath              string
	TypesOfVulnerabilitiesToIgnore  string
	FilesOrPathsToIgnore            string
	ReturnErrorIfFoundVulnerability bool
	ProjectPath                     string
	WorkDir                         *workdir.WorkDir
	FilterPath                      string
	EnableGitHistoryAnalysis        bool
	CertInsecureSkipVerify          bool
	CertPath                        string
	EnableCommitAuthor              bool
	RepositoryName                  string
	FalsePositiveHashes             string
	RiskAcceptHashes                string
	ToolsToIgnore                   string
	ContainerBindProjectPath        string
}

//nolint
func (c *Config) SetConfigsFromViper() {
	viper.SetConfigFile(c.ConfigFilePath)
	_ = viper.ReadInConfig()

	c.SetHorusecAPIURI(viper.GetString(c.toLowerCamel(EnvHorusecAPIUri)))
	c.SetTimeoutInSecondsRequest(viper.GetInt64(c.toLowerCamel(EnvTimeoutInSecondsRequest)))
	c.SetTimeoutInSecondsAnalysis(viper.GetInt64(c.toLowerCamel(EnvTimeoutInSecondsAnalysis)))
	c.SetMonitorRetryInSeconds(viper.GetInt64(c.toLowerCamel(EnvMonitorRetryInSeconds)))
	c.SetRepositoryAuthorization(viper.GetString(c.toLowerCamel(EnvRepositoryAuthorization)))
	c.SetPrintOutputType(viper.GetString(c.toLowerCamel(EnvPrintOutputType)))
	c.SetJSONOutputFilePath(viper.GetString(c.toLowerCamel(EnvJSONOutputFilePath)))
	c.SetTypesOfVulnerabilitiesToIgnore(viper.GetString(c.toLowerCamel(EnvTypesOfVulnerabilitiesToIgnore)))
	c.SetFilesOrPathsToIgnore(viper.GetString(c.toLowerCamel(EnvFilesOrPathsToIgnore)))
	c.SetReturnErrorIfFoundVulnerability(viper.GetBool(c.toLowerCamel(EnvReturnErrorIfFoundVulnerability)))
	c.SetProjectPath(viper.GetString(c.toLowerCamel(EnvProjectPath)))
	c.SetWorkDir(viper.Get(c.toLowerCamel(EnvWorkDirPath)))
	c.SetFilterPath(viper.GetString(c.toLowerCamel(EnvFilterPath)))
	c.SetEnableGitHistoryAnalysis(viper.GetBool(c.toLowerCamel(EnvEnableGitHistoryAnalysis)))
	c.SetCertInsecureSkipVerify(viper.GetBool(c.toLowerCamel(EnvCertInsecureSkipVerify)))
	c.SetCertPath(viper.GetString(c.toLowerCamel(EnvCertPath)))
	c.SetEnableCommitAuthor(viper.GetBool(c.toLowerCamel(EnvEnableCommitAuthor)))
	c.SetRepositoryName(viper.GetString(c.toLowerCamel(EnvRepositoryName)))
	c.SetFalsePositiveHashes(viper.GetString(c.toLowerCamel(EnvFalsePositiveHashes)))
	c.SetRiskAcceptHashes(viper.GetString(c.toLowerCamel(EnvRiskAcceptHashes)))
	c.SetToolsToIgnore(viper.GetString(c.toLowerCamel(EnvToolsToIgnore)))
	c.SetHeaders(viper.GetStringMapString(c.toLowerCamel(EnvHeaders)))
	c.SetContainerBindProjectPath(viper.GetString(c.toLowerCamel(EnvContainerBindProjectPath)))
}

//nolint
func (c *Config) SetConfigsFromEnvironments() {
	c.SetHorusecAPIURI(env.GetEnvOrDefault(EnvHorusecAPIUri, c.HorusecAPIUri))
	c.SetTimeoutInSecondsRequest(env.GetEnvOrDefaultInt64(EnvTimeoutInSecondsRequest, c.TimeoutInSecondsRequest))
	c.SetTimeoutInSecondsAnalysis(env.GetEnvOrDefaultInt64(EnvTimeoutInSecondsAnalysis, c.TimeoutInSecondsAnalysis))
	c.SetMonitorRetryInSeconds(env.GetEnvOrDefaultInt64(EnvMonitorRetryInSeconds, c.MonitorRetryInSeconds))
	c.SetRepositoryAuthorization(env.GetEnvOrDefault(EnvRepositoryAuthorization, c.RepositoryAuthorization))
	c.SetPrintOutputType(env.GetEnvOrDefault(EnvPrintOutputType, c.PrintOutputType))
	c.SetJSONOutputFilePath(env.GetEnvOrDefault(EnvJSONOutputFilePath, c.JSONOutputFilePath))
	c.SetTypesOfVulnerabilitiesToIgnore(env.GetEnvOrDefault(EnvTypesOfVulnerabilitiesToIgnore,
		c.TypesOfVulnerabilitiesToIgnore))
	c.SetFilesOrPathsToIgnore(env.GetEnvOrDefault(EnvFilesOrPathsToIgnore, c.FilesOrPathsToIgnore))
	c.SetReturnErrorIfFoundVulnerability(
		env.GetEnvOrDefaultBool(EnvReturnErrorIfFoundVulnerability, c.ReturnErrorIfFoundVulnerability))
	c.SetProjectPath(env.GetEnvOrDefault(EnvProjectPath, c.ProjectPath))
	c.SetFilterPath(env.GetEnvOrDefault(EnvFilterPath, c.FilterPath))
	c.SetEnableGitHistoryAnalysis(env.GetEnvOrDefaultBool(EnvEnableGitHistoryAnalysis, c.EnableGitHistoryAnalysis))
	c.SetCertInsecureSkipVerify(env.GetEnvOrDefaultBool(EnvCertInsecureSkipVerify, c.CertInsecureSkipVerify))
	c.SetCertPath(env.GetEnvOrDefault(EnvCertPath, c.CertPath))
	c.SetEnableCommitAuthor(env.GetEnvOrDefaultBool(EnvEnableCommitAuthor, c.EnableCommitAuthor))
	c.SetRepositoryName(env.GetEnvOrDefault(EnvRepositoryName, c.RepositoryName))
	c.SetFalsePositiveHashes(env.GetEnvOrDefault(EnvFalsePositiveHashes, c.FalsePositiveHashes))
	c.SetRiskAcceptHashes(env.GetEnvOrDefault(EnvRiskAcceptHashes, c.RiskAcceptHashes))
	c.SetToolsToIgnore(env.GetEnvOrDefault(EnvToolsToIgnore, c.ToolsToIgnore))
	c.SetHeaders(env.GetEnvOrDefault(EnvHeaders, c.Headers))
	c.SetContainerBindProjectPath(env.GetEnvOrDefault(EnvContainerBindProjectPath, c.ContainerBindProjectPath))
}

func (c *Config) GetHorusecAPIUri() string {
	return c.HorusecAPIUri
}

func (c *Config) SetHorusecAPIURI(horusecAPIURI string) {
	c.HorusecAPIUri = text.GetStringValueOrDefault(horusecAPIURI, "http://0.0.0.0:8000")
}

func (c *Config) GetTimeoutInSecondsRequest() int64 {
	return c.TimeoutInSecondsRequest
}

func (c *Config) SetTimeoutInSecondsRequest(timeoutInSecondsRequest int64) {
	c.TimeoutInSecondsRequest = text.GetInt64ValueOrDefault(timeoutInSecondsRequest, int64(300))
}

func (c *Config) GetTimeoutInSecondsAnalysis() int64 {
	return c.TimeoutInSecondsAnalysis
}

func (c *Config) SetTimeoutInSecondsAnalysis(timeoutInSecondsAnalysis int64) {
	c.TimeoutInSecondsAnalysis = text.GetInt64ValueOrDefault(timeoutInSecondsAnalysis, int64(600))
}

func (c *Config) GetMonitorRetryInSeconds() int64 {
	return c.MonitorRetryInSeconds
}

func (c *Config) SetMonitorRetryInSeconds(retryInterval int64) {
	c.MonitorRetryInSeconds = text.GetInt64ValueOrDefault(retryInterval, int64(15))
}

func (c *Config) GetRepositoryAuthorization() string {
	return c.RepositoryAuthorization
}

func (c *Config) SetRepositoryAuthorization(repositoryAuthorization string) {
	c.RepositoryAuthorization = text.GetStringValueOrDefault(repositoryAuthorization, uuid.Nil.String())
}

func (c *Config) GetPrintOutputType() string {
	return c.PrintOutputType
}

func (c *Config) SetPrintOutputType(printOutputType string) {
	c.PrintOutputType = text.GetStringValueOrDefault(printOutputType, "text")
}

func (c *Config) GetJSONOutputFilePath() string {
	return c.JSONOutputFilePath
}

func (c *Config) SetJSONOutputFilePath(jsonOutputFilePath string) {
	c.JSONOutputFilePath = text.GetStringValueOrDefault(jsonOutputFilePath, "")
}

func (c *Config) GetTypesOfVulnerabilitiesToIgnore() string {
	return c.TypesOfVulnerabilitiesToIgnore
}

func (c *Config) SetTypesOfVulnerabilitiesToIgnore(typesOfVulnerabilitiesToIgnore string) {
	c.TypesOfVulnerabilitiesToIgnore = text.GetStringValueOrDefault(typesOfVulnerabilitiesToIgnore, "")
}

func (c *Config) GetFilesOrPathsToIgnore() string {
	return c.FilesOrPathsToIgnore
}

func (c *Config) SetFilesOrPathsToIgnore(filesOrPaths string) {
	c.FilesOrPathsToIgnore = text.GetStringValueOrDefault(filesOrPaths, "")
}

func (c *Config) GetReturnErrorIfFoundVulnerability() bool {
	return c.ReturnErrorIfFoundVulnerability
}

func (c *Config) SetReturnErrorIfFoundVulnerability(returnError bool) {
	c.ReturnErrorIfFoundVulnerability = returnError
}

func (c *Config) GetProjectPath() string {
	return c.ProjectPath
}

func (c *Config) SetProjectPath(projectPath string) {
	path, err := os.Getwd()
	if err != nil {
		c.ProjectPath = text.GetStringValueOrDefault(projectPath, "./")
	} else {
		c.ProjectPath = text.GetStringValueOrDefault(projectPath, path)
	}
}

func (c *Config) SetFilterPath(filterPath string) {
	c.FilterPath = filterPath
}

func (c *Config) GetFilterPath() string {
	return c.FilterPath
}

func (c *Config) GetWorkDir() *workdir.WorkDir {
	return c.WorkDir
}

func (c *Config) SetWorkDir(toParse interface{}) {
	if c.netCoreKeyIsDeprecated(toParse) {
		logger.LogWarnWithLevel(messages.MsgWarnNetCoreDeprecated, logger.WarnLevel)
	}
	c.WorkDir = &workdir.WorkDir{}
	c.WorkDir.ParseInterfaceToStruct(toParse)
}

// nolint:gocyclo is necessary to check all validations
func (c *Config) netCoreKeyIsDeprecated(toParse interface{}) bool {
	workdirParsed, ok := toParse.(map[string]interface{})
	if ok && workdirParsed["netcore"] != nil {
		netCore, ok := workdirParsed["netcore"].([]interface{})
		if ok && netCore != nil && len(netCore) > 0 {
			return true
		}
	}
	return false
}

func (c *Config) GetEnableGitHistoryAnalysis() bool {
	return c.EnableGitHistoryAnalysis
}

func (c *Config) SetEnableGitHistoryAnalysis(enableGitHistoryAnalysis bool) {
	c.EnableGitHistoryAnalysis = enableGitHistoryAnalysis
}

func (c *Config) GetCertInsecureSkipVerify() bool {
	return c.CertInsecureSkipVerify
}

func (c *Config) SetCertInsecureSkipVerify(certInsecureSkipVerify bool) {
	c.CertInsecureSkipVerify = certInsecureSkipVerify
}

func (c *Config) IsEmptyRepositoryAuthorization() bool {
	return c.RepositoryAuthorization == "" || c.RepositoryAuthorization == uuid.Nil.String()
}

func (c *Config) ToBytes(isMarshalIndent bool) (bytes []byte) {
	if isMarshalIndent {
		bytes, _ = json.MarshalIndent(c, "", "  ")
	} else {
		bytes, _ = json.Marshal(c)
	}

	return bytes
}

func (c *Config) toLowerCamel(value string) string {
	return strcase.ToLowerCamel(strcase.ToSnake(value))
}

func (c *Config) SetCertPath(certPath string) {
	c.CertPath = text.GetStringValueOrDefault(certPath, "")
}

func (c *Config) GetCertPath() string {
	return c.CertPath
}

func (c *Config) SetEnableCommitAuthor(isEnable bool) {
	c.EnableCommitAuthor = isEnable
}

func (c *Config) IsCommitAuthorEnable() bool {
	return c.EnableCommitAuthor
}

func (c *Config) SetRepositoryName(repositoryName string) {
	c.RepositoryName = repositoryName
}

func (c *Config) GetRepositoryName() string {
	return c.RepositoryName
}

func (c *Config) GetRiskAcceptHashes() string {
	return c.RiskAcceptHashes
}

func (c *Config) GetRiskAcceptHashesList() (list []string) {
	for _, item := range strings.Split(c.RiskAcceptHashes, ",") {
		itemFormatted := strings.TrimSpace(item)
		if len(itemFormatted) > 0 {
			list = append(list, itemFormatted)
		}
	}
	return list
}

func (c *Config) SetRiskAcceptHashes(riskAccept string) {
	c.RiskAcceptHashes = riskAccept
}

func (c *Config) GetFalsePositiveHashes() string {
	return c.FalsePositiveHashes
}

func (c *Config) GetFalsePositiveHashesList() (list []string) {
	for _, item := range strings.Split(c.FalsePositiveHashes, ",") {
		itemFormatted := strings.TrimSpace(item)
		if len(itemFormatted) > 0 {
			list = append(list, itemFormatted)
		}
	}
	return list
}

func (c *Config) SetFalsePositiveHashes(falsePositive string) {
	c.FalsePositiveHashes = falsePositive
}

func (c *Config) GetToolsToIgnore() string {
	return c.ToolsToIgnore
}

func (c *Config) SetToolsToIgnore(toolsToIgnore string) {
	c.ToolsToIgnore = toolsToIgnore
}

func (c *Config) GetHeaders() (headers map[string]string) {
	err := json.Unmarshal([]byte(c.Headers), &headers)
	logger.LogErrorWithLevel("Error on unmarshal headers to map", err, logger.ErrorLevel)
	return headers
}

func (c *Config) SetHeaders(headers interface{}) {
	if headers != nil && headers != "" {
		headersString, ok := headers.(string)
		if ok {
			c.Headers = headersString
		} else {
			bytes, err := json.Marshal(headers)
			logger.LogErrorWithLevel("Error on marshal headers to bytes", err, logger.ErrorLevel)
			c.Headers = string(bytes)
		}
	}
}

func (c *Config) GetContainerBindProjectPath() string {
	return c.ContainerBindProjectPath
}

func (c *Config) SetContainerBindProjectPath(containerBindProjectPath string) {
	c.ContainerBindProjectPath = containerBindProjectPath
}
