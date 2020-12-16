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
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	utilsJson "github.com/ZupIT/horusec/development-kit/pkg/utils/json"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/valueordefault"
	"github.com/ZupIT/horusec/horusec-cli/internal/entities/toolsconfig"
	"github.com/spf13/cobra"
	"path/filepath"
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"

	"github.com/iancoleman/strcase"

	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/ZupIT/horusec/horusec-cli/internal/entities/workdir"
	"github.com/google/uuid"
	"github.com/spf13/viper"
)

//nolint
func (c *Config) NewConfigsFromCobraAndLoadsCmdStartFlags(cmd *cobra.Command) IConfig {
	cmd.PersistentFlags().
		Int64VarP(&c.monitorRetryInSeconds, "monitor-retry-count", "m", c.GetMonitorRetryInSeconds(),
			"The number of retries for the monitor.")
	cmd.PersistentFlags().
		StringVarP(&c.printOutputType, "output-format", "o", c.GetPrintOutputType(),
			"The format for the output to be shown. Options are: text (stdout), json, sonarqube")
	cmd.PersistentFlags().
		StringSliceVarP(&c.severitiesToIgnore, "ignore-severity", "s", c.GetSeveritiesToIgnore(),
			"The level of vulnerabilities to ignore in the output. Example: -s=\"LOW, MEDIUM, NOSEC\"")
	cmd.PersistentFlags().
		StringVarP(&c.jsonOutputFilePath, "json-output-file", "O", c.GetJSONOutputFilePath(),
			"If your pass output-format you can configure the output JSON location. Example: -O=\"/tmp/output.json\"")
	cmd.PersistentFlags().
		StringSliceVarP(&c.filesOrPathsToIgnore, "ignore", "i", c.GetFilesOrPathsToIgnore(),
			"Paths to ignore in the analysis. Example: -i=\"/home/user/project/assets, /home/user/project/deployments\"")
	cmd.PersistentFlags().
		StringVarP(&c.horusecAPIUri, "horusec-url", "u", c.GetHorusecAPIUri(),
			"The Horusec API address to access the analysis engine")
	cmd.PersistentFlags().
		Int64VarP(&c.timeoutInSecondsRequest, "request-timeout", "r", c.GetTimeoutInSecondsRequest(),
			"The timeout threshold for the request to the Horusec API")
	cmd.PersistentFlags().
		Int64VarP(&c.timeoutInSecondsAnalysis, "analysis-timeout", "t", c.GetTimeoutInSecondsAnalysis(),
			"The timeout threshold for the Horusec CLI wait for the analysis to complete.")
	cmd.PersistentFlags().
		StringVarP(&c.repositoryAuthorization, "authorization", "a", c.GetRepositoryAuthorization(),
			"The authorization token for the Horusec API")
	cmd.PersistentFlags().
		StringToStringVar(&c.headers, "headers", c.GetHeaders(),
			"The headers dynamic to send on request in Horusec API. Example --headers=\"{\"X-Auth-Service\": \"my-value\"}\"")
	cmd.PersistentFlags().
		BoolVarP(&c.returnErrorIfFoundVulnerability, "return-error", "e", c.GetReturnErrorIfFoundVulnerability(),
			"The return-error is the option to check if you can return \"exit(1)\" if found vulnerabilities. Example -e=\"true\"")
	cmd.PersistentFlags().
		StringVarP(&c.projectPath, "project-path", "p", c.GetProjectPath(),
			"Path to run an analysis in your project")
	cmd.PersistentFlags().
		StringVarP(&c.filterPath, "filter-path", "f", c.GetFilterPath(),
			"Filter the path to run the analysis")
	cmd.PersistentFlags().
		BoolVar(&c.enableGitHistoryAnalysis, "enable-git-history", c.GetEnableGitHistoryAnalysis(),
			"When this value is \"true\" we will run tool gitleaks and search vulnerability in all git history of the project. Example --enable-git-history=\"true\"")
	cmd.PersistentFlags().
		BoolVarP(&c.certInsecureSkipVerify, "insecure-skip-verify", "S", c.GetCertInsecureSkipVerify(),
			"Insecure skip verify cert authority. PLEASE, try not to use it. Example -S=\"true\"")
	cmd.PersistentFlags().
		StringVarP(&c.certPath, "certificate-path", "C", c.GetCertPath(),
			"Path to certificate of authority. Example -C=\"/example/ca.crt\"")
	cmd.PersistentFlags().
		BoolVarP(&c.enableCommitAuthor, "enable-commit-author", "G", c.GetEnableCommitAuthor(),
			"Used to enable or disable search with vulnerability author. Example -G=\"true\"")
	cmd.PersistentFlags().
		StringVarP(&c.repositoryName, "repository-name", "n", c.GetRepositoryName(),
			"Used to send repository name to horus server. Example -n=\"horus\"")
	cmd.PersistentFlags().
		StringSliceVarP(&c.falsePositiveHashes, "false-positive", "F", c.GetFalsePositiveHashes(),
			"Used to ignore a vulnerability by hash and setting it to be of the false positive type. Example -F=\"hash1, hash2\"")
	cmd.PersistentFlags().
		StringSliceVarP(&c.riskAcceptHashes, "risk-accept", "R", c.GetRiskAcceptHashes(),
			"Used to ignore a vulnerability by hash and setting it to be of the risk accept type. Example -R=\"hash3, hash4\"")
	cmd.PersistentFlags().
		StringSliceVarP(&c.toolsToIgnore, "tools-ignore", "T", c.GetToolsToIgnore(),
			"Tools to ignore in the analysis. Available are: GoSec,SecurityCodeScan,Brakeman,Safety,Bandit,NpmAudit,YarnAudit,SpotBugs,HorusecKotlin,HorusecJava,HorusecLeaks,GitLeaks,TfSec,Semgrep,HorusecCsharp,HorusecNodeJS,HorusecKubernetes,Eslint,PhpCS,Flawfinder. Example: -T=\"GoSec, Brakeman\"")
	cmd.PersistentFlags().
		StringVarP(&c.containerBindProjectPath, "container-bind-project-path", "P", c.GetContainerBindProjectPath(),
			"Used to pass project path in host when running horusec cli inside a container.")
	return c
}

//nolint
func (c *Config) NewConfigsFromViper() IConfig {
	viper.SetConfigFile(c.GetConfigFilePath())
	logger.LogErrorWithLevel("Error on read config file path", viper.ReadInConfig(), logger.ErrorLevel)

	c.SetHorusecAPIURI(viper.GetString(c.toLowerCamel(EnvHorusecAPIUri)))
	c.SetTimeoutInSecondsRequest(viper.GetInt64(c.toLowerCamel(EnvTimeoutInSecondsRequest)))
	c.SetTimeoutInSecondsAnalysis(viper.GetInt64(c.toLowerCamel(EnvTimeoutInSecondsAnalysis)))
	c.SetMonitorRetryInSeconds(viper.GetInt64(c.toLowerCamel(EnvMonitorRetryInSeconds)))
	c.SetRepositoryAuthorization(viper.GetString(c.toLowerCamel(EnvRepositoryAuthorization)))
	c.SetPrintOutputType(viper.GetString(c.toLowerCamel(EnvPrintOutputType)))
	c.SetJSONOutputFilePath(viper.GetString(c.toLowerCamel(EnvJSONOutputFilePath)))
	c.SetSeveritiesToIgnore(viper.GetStringSlice(c.toLowerCamel(EnvSeveritiesToIgnore)))
	c.SetFilesOrPathsToIgnore(viper.GetStringSlice(c.toLowerCamel(EnvFilesOrPathsToIgnore)))
	c.SetReturnErrorIfFoundVulnerability(viper.GetBool(c.toLowerCamel(EnvReturnErrorIfFoundVulnerability)))
	c.SetProjectPath(viper.GetString(c.toLowerCamel(EnvProjectPath)))
	c.SetWorkDir(viper.Get(c.toLowerCamel(EnvWorkDirPath)))
	c.SetFilterPath(viper.GetString(c.toLowerCamel(EnvFilterPath)))
	c.SetEnableGitHistoryAnalysis(viper.GetBool(c.toLowerCamel(EnvEnableGitHistoryAnalysis)))
	c.SetCertInsecureSkipVerify(viper.GetBool(c.toLowerCamel(EnvCertInsecureSkipVerify)))
	c.SetCertPath(viper.GetString(c.toLowerCamel(EnvCertPath)))
	c.SetEnableCommitAuthor(viper.GetBool(c.toLowerCamel(EnvEnableCommitAuthor)))
	c.SetRepositoryName(viper.GetString(c.toLowerCamel(EnvRepositoryName)))
	c.SetFalsePositiveHashes(viper.GetStringSlice(c.toLowerCamel(EnvFalsePositiveHashes)))
	c.SetRiskAcceptHashes(viper.GetStringSlice(c.toLowerCamel(EnvRiskAcceptHashes)))
	c.SetToolsToIgnore(viper.GetStringSlice(c.toLowerCamel(EnvToolsToIgnore)))
	c.SetHeaders(viper.GetStringMapString(c.toLowerCamel(EnvHeaders)))
	c.SetContainerBindProjectPath(viper.GetString(c.toLowerCamel(EnvContainerBindProjectPath)))
	c.SetToolsConfig(viper.Get(c.toLowerCamel(EnvToolsConfig)))
	return c
}

//nolint
func (c *Config) NewConfigsFromEnvironments() IConfig {
	c.SetHorusecAPIURI(env.GetEnvOrDefault(EnvHorusecAPIUri, c.horusecAPIUri))
	c.SetTimeoutInSecondsRequest(env.GetEnvOrDefaultInt64(EnvTimeoutInSecondsRequest, c.timeoutInSecondsRequest))
	c.SetTimeoutInSecondsAnalysis(env.GetEnvOrDefaultInt64(EnvTimeoutInSecondsAnalysis, c.timeoutInSecondsAnalysis))
	c.SetMonitorRetryInSeconds(env.GetEnvOrDefaultInt64(EnvMonitorRetryInSeconds, c.monitorRetryInSeconds))
	c.SetRepositoryAuthorization(env.GetEnvOrDefault(EnvRepositoryAuthorization, c.repositoryAuthorization))
	c.SetPrintOutputType(env.GetEnvOrDefault(EnvPrintOutputType, c.printOutputType))
	c.SetJSONOutputFilePath(env.GetEnvOrDefault(EnvJSONOutputFilePath, c.jsonOutputFilePath))
	c.SetSeveritiesToIgnore(c.factoryParseInputToSliceString(env.GetEnvOrDefaultInterface(EnvSeveritiesToIgnore, c.severitiesToIgnore)))
	c.SetFilesOrPathsToIgnore(c.factoryParseInputToSliceString(env.GetEnvOrDefaultInterface(EnvFilesOrPathsToIgnore, c.filesOrPathsToIgnore)))
	c.SetReturnErrorIfFoundVulnerability(env.GetEnvOrDefaultBool(EnvReturnErrorIfFoundVulnerability, c.returnErrorIfFoundVulnerability))
	c.SetProjectPath(env.GetEnvOrDefault(EnvProjectPath, c.projectPath))
	c.SetFilterPath(env.GetEnvOrDefault(EnvFilterPath, c.filterPath))
	c.SetEnableGitHistoryAnalysis(env.GetEnvOrDefaultBool(EnvEnableGitHistoryAnalysis, c.enableGitHistoryAnalysis))
	c.SetCertInsecureSkipVerify(env.GetEnvOrDefaultBool(EnvCertInsecureSkipVerify, c.certInsecureSkipVerify))
	c.SetCertPath(env.GetEnvOrDefault(EnvCertPath, c.certPath))
	c.SetEnableCommitAuthor(env.GetEnvOrDefaultBool(EnvEnableCommitAuthor, c.enableCommitAuthor))
	c.SetRepositoryName(env.GetEnvOrDefault(EnvRepositoryName, c.repositoryName))
	c.SetFalsePositiveHashes(c.factoryParseInputToSliceString(env.GetEnvOrDefaultInterface(EnvFalsePositiveHashes, c.falsePositiveHashes)))
	c.SetRiskAcceptHashes(c.factoryParseInputToSliceString(env.GetEnvOrDefaultInterface(EnvRiskAcceptHashes, c.riskAcceptHashes)))
	c.SetToolsToIgnore(c.factoryParseInputToSliceString(env.GetEnvOrDefaultInterface(EnvToolsToIgnore, c.toolsToIgnore)))
	c.SetHeaders(env.GetEnvOrDefaultInterface(EnvHeaders, c.headers))
	c.SetContainerBindProjectPath(env.GetEnvOrDefault(EnvContainerBindProjectPath, c.containerBindProjectPath))
	return c
}

func (c *Config) GetConfigFilePath() string {
	return c.configFilePath
}

func (c *Config) SetConfigFilePath(configFilePath string) {
	c.configFilePath = valueordefault.GetPathOrCurrentPath(configFilePath)
}

func (c *Config) GetHorusecAPIUri() string {
	return valueordefault.GetStringValueOrDefault(c.horusecAPIUri, "http://0.0.0.0:8000")
}

func (c *Config) SetHorusecAPIURI(horusecAPIURI string) {
	c.horusecAPIUri = horusecAPIURI
}

func (c *Config) GetTimeoutInSecondsRequest() int64 {
	return valueordefault.GetInt64ValueOrDefault(c.timeoutInSecondsRequest, int64(300))
}

func (c *Config) SetTimeoutInSecondsRequest(timeoutInSecondsRequest int64) {
	c.timeoutInSecondsRequest = timeoutInSecondsRequest
}

func (c *Config) GetTimeoutInSecondsAnalysis() int64 {
	return valueordefault.GetInt64ValueOrDefault(c.timeoutInSecondsAnalysis, int64(600))
}

func (c *Config) SetTimeoutInSecondsAnalysis(timeoutInSecondsAnalysis int64) {
	c.timeoutInSecondsAnalysis = timeoutInSecondsAnalysis
}

func (c *Config) GetMonitorRetryInSeconds() int64 {
	return valueordefault.GetInt64ValueOrDefault(c.monitorRetryInSeconds, int64(15))
}

func (c *Config) SetMonitorRetryInSeconds(retryInterval int64) {
	c.monitorRetryInSeconds = retryInterval
}

func (c *Config) GetRepositoryAuthorization() string {
	return valueordefault.GetStringValueOrDefault(c.repositoryAuthorization, uuid.Nil.String())
}

func (c *Config) SetRepositoryAuthorization(repositoryAuthorization string) {
	c.repositoryAuthorization = repositoryAuthorization
}

func (c *Config) GetPrintOutputType() string {
	return valueordefault.GetStringValueOrDefault(c.printOutputType, "text")
}

func (c *Config) SetPrintOutputType(printOutputType string) {
	c.printOutputType = printOutputType
}

func (c *Config) GetJSONOutputFilePath() string {
	return valueordefault.GetStringValueOrDefault(c.jsonOutputFilePath, "")
}

func (c *Config) SetJSONOutputFilePath(jsonOutputFilePath string) {
	c.jsonOutputFilePath = jsonOutputFilePath
}

func (c *Config) GetSeveritiesToIgnore() []string {
	return valueordefault.GetSliceStringValueOrDefault(c.severitiesToIgnore, []string{"AUDIT", "INFO"})
}

func (c *Config) SetSeveritiesToIgnore(severitiesToIgnore []string) {
	c.severitiesToIgnore = c.factoryParseInputToSliceString(severitiesToIgnore)
}

func (c *Config) GetFilesOrPathsToIgnore() []string {
	return c.filesOrPathsToIgnore
}

func (c *Config) SetFilesOrPathsToIgnore(filesOrPaths []string) {
	c.filesOrPathsToIgnore = c.factoryParseInputToSliceString(filesOrPaths)
}

func (c *Config) GetReturnErrorIfFoundVulnerability() bool {
	return c.returnErrorIfFoundVulnerability
}

func (c *Config) SetReturnErrorIfFoundVulnerability(returnError bool) {
	c.returnErrorIfFoundVulnerability = returnError
}

func (c *Config) GetProjectPath() string {
	return valueordefault.GetPathOrCurrentPath(c.projectPath)
}

func (c *Config) SetProjectPath(projectPath string) {
	c.projectPath = projectPath
}

func (c *Config) GetFilterPath() string {
	return c.filterPath
}

func (c *Config) SetFilterPath(filterPath string) {
	c.filterPath = filterPath
}

func (c *Config) GetWorkDir() *workdir.WorkDir {
	return valueordefault.GetInterfaceValueOrDefault(c.workDir, workdir.NewWorkDir()).(*workdir.WorkDir)
}

func (c *Config) SetWorkDir(input interface{}) {
	if c.netCoreKeyIsDeprecated(input) {
		logger.LogWarnWithLevel(messages.MsgWarnNetCoreDeprecated, logger.WarnLevel)
	}
	if input != nil {
		c.workDir = c.workDir.ParseInterfaceToStruct(input)
	}
	if c.workDir == nil {
		c.workDir = workdir.NewWorkDir()
	}
}

func (c *Config) GetEnableGitHistoryAnalysis() bool {
	return c.enableGitHistoryAnalysis
}

func (c *Config) SetEnableGitHistoryAnalysis(enableGitHistoryAnalysis bool) {
	c.enableGitHistoryAnalysis = enableGitHistoryAnalysis
}

func (c *Config) GetCertInsecureSkipVerify() bool {
	return c.certInsecureSkipVerify
}

func (c *Config) SetCertInsecureSkipVerify(certInsecureSkipVerify bool) {
	c.certInsecureSkipVerify = certInsecureSkipVerify
}

func (c *Config) GetCertPath() string {
	return valueordefault.GetStringValueOrDefault(c.certPath, "")
}

func (c *Config) SetCertPath(certPath string) {
	c.certPath = certPath
}

func (c *Config) GetEnableCommitAuthor() bool {
	return c.enableCommitAuthor
}

func (c *Config) SetEnableCommitAuthor(isEnable bool) {
	c.enableCommitAuthor = isEnable
}

func (c *Config) GetRepositoryName() string {
	return valueordefault.GetStringValueOrDefault(c.repositoryName, "")
}

func (c *Config) SetRepositoryName(repositoryName string) {
	c.repositoryName = repositoryName
}

func (c *Config) GetRiskAcceptHashes() (output []string) {
	return c.riskAcceptHashes
}

func (c *Config) SetRiskAcceptHashes(riskAccept []string) {
	c.riskAcceptHashes = c.factoryParseInputToSliceString(riskAccept)
}

func (c *Config) GetFalsePositiveHashes() (output []string) {
	return c.falsePositiveHashes
}

func (c *Config) SetFalsePositiveHashes(falsePositive []string) {
	c.falsePositiveHashes = c.factoryParseInputToSliceString(falsePositive)
}

func (c *Config) GetToolsToIgnore() (output []string) {
	return c.toolsToIgnore
}

func (c *Config) SetToolsToIgnore(toolsToIgnore []string) {
	if len(toolsToIgnore) > 0 {
		logger.LogWarnWithLevel(messages.MsgWarnToolsToIgnoreDeprecated, logger.WarnLevel)
	}
	c.toolsToIgnore = c.factoryParseInputToSliceString(toolsToIgnore)
}

func (c *Config) GetHeaders() (headers map[string]string) {
	return c.headers
}

func (c *Config) SetHeaders(headers interface{}) {
	output, err := utilsJson.ConvertInterfaceToMapString(headers)
	logger.LogErrorWithLevel("Error on marshal headers to bytes", err, logger.PanicLevel)
	c.headers = output
}

func (c *Config) GetContainerBindProjectPath() string {
	return c.containerBindProjectPath
}

func (c *Config) SetContainerBindProjectPath(containerBindProjectPath string) {
	c.containerBindProjectPath = containerBindProjectPath
}

func (c *Config) GetIsTimeout() bool {
	return c.isTimeout
}

func (c *Config) SetIsTimeout(isTimeout bool) {
	c.isTimeout = isTimeout
}

func (c *Config) GetToolsConfig() map[tools.Tool]toolsconfig.ToolConfig {
	return valueordefault.GetInterfaceValueOrDefault(
		c.toolsConfig, toolsconfig.NewMapToolConfig()).(map[tools.Tool]toolsconfig.ToolConfig)
}

func (c *Config) SetToolsConfig(toolsConfig interface{}) {
	c.toolsConfig = toolsconfig.ParseInterfaceToMapToolsConfig(toolsConfig)
}

func (c *Config) IsEmptyRepositoryAuthorization() bool {
	return c.repositoryAuthorization == "" || c.repositoryAuthorization == uuid.Nil.String()
}

//nolint:funlen parse struct is necessary > 15 lines
func (c *Config) toMap() map[string]interface{} {
	return map[string]interface{}{
		"configFilePath":                  c.configFilePath,
		"horusecAPIUri":                   c.horusecAPIUri,
		"repositoryAuthorization":         c.repositoryAuthorization,
		"filterPath":                      c.filterPath,
		"certPath":                        c.certPath,
		"repositoryName":                  c.repositoryName,
		"printOutputType":                 c.printOutputType,
		"jsonOutputFilePath":              c.jsonOutputFilePath,
		"projectPath":                     c.projectPath,
		"containerBindProjectPath":        c.containerBindProjectPath,
		"timeoutInSecondsRequest":         c.timeoutInSecondsRequest,
		"timeoutInSecondsAnalysis":        c.timeoutInSecondsAnalysis,
		"monitorRetryInSeconds":           c.monitorRetryInSeconds,
		"isTimeout":                       c.isTimeout,
		"returnErrorIfFoundVulnerability": c.returnErrorIfFoundVulnerability,
		"enableGitHistoryAnalysis":        c.enableGitHistoryAnalysis,
		"certInsecureSkipVerify":          c.certInsecureSkipVerify,
		"enableCommitAuthor":              c.enableCommitAuthor,
		"severitiesToIgnore":              c.severitiesToIgnore,
		"filesOrPathsToIgnore":            c.filesOrPathsToIgnore,
		"falsePositiveHashes":             c.falsePositiveHashes,
		"riskAcceptHashes":                c.riskAcceptHashes,
		"toolsToIgnore":                   c.toolsToIgnore,
		"headers":                         c.headers,
		"toolsConfig":                     c.toolsConfig,
		"workDir":                         c.workDir,
	}
}

func (c *Config) ToBytes(isMarshalIndent bool) (bytes []byte) {
	if isMarshalIndent {
		bytes, _ = json.MarshalIndent(c.toMap(), "", "  ")
	} else {
		bytes, _ = json.Marshal(c.toMap())
	}

	return bytes
}

func (c *Config) NormalizeConfigs() IConfig {
	if c.GetJSONOutputFilePath() != "" {
		absJSONOutputFilePath, _ := filepath.Abs(c.GetJSONOutputFilePath())
		c.SetJSONOutputFilePath(absJSONOutputFilePath)
	}
	projectPath, _ := filepath.Abs(c.GetProjectPath())
	c.SetProjectPath(projectPath)
	return c
}

func (c *Config) toLowerCamel(value string) string {
	return strcase.ToLowerCamel(strcase.ToSnake(value))
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

func (c *Config) factoryParseInputToSliceString(input interface{}) []string {
	if _, ok := input.(string); ok {
		return c.replaceCommaToSpaceString(input.(string))
	}
	if _, ok := input.([]string); ok {
		return c.replaceCommaToSpaceSliceString(input.([]string))
	}
	return []string{}
}

func (c *Config) replaceCommaToSpaceString(input string) (response []string) {
	if input != "" {
		for _, item := range strings.Split(strings.TrimSpace(input), ",") {
			newItem := strings.ReplaceAll(strings.TrimSpace(item), ",", "")
			response = append(response, newItem)
		}
	}
	return response
}

func (c *Config) replaceCommaToSpaceSliceString(input []string) (response []string) {
	for _, item := range input {
		newItem := strings.ReplaceAll(strings.TrimSpace(item), ",", "")
		response = append(response, newItem)
	}
	return response
}
