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
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/iancoleman/strcase"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	enumsVulnerability "github.com/ZupIT/horusec-devkit/pkg/enums/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/utils/env"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	"github.com/ZupIT/horusec/config/dist"
	customImages "github.com/ZupIT/horusec/internal/entities/custom_images"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/entities/workdir"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	utilsJson "github.com/ZupIT/horusec/internal/utils/json"
	"github.com/ZupIT/horusec/internal/utils/valueordefault"
)

func NewConfig() IConfig {
	return &Config{
		falsePositiveHashes:      []string{},
		riskAcceptHashes:         []string{},
		severitiesToIgnore:       []string{},
		showVulnerabilitiesTypes: []string{},
		headers:                  map[string]string{},
		workDir:                  workdir.NewWorkDir(),
		toolsConfig:              toolsconfig.ParseInterfaceToMapToolsConfig(toolsconfig.ToolConfig{}),
		customImages:             customImages.NewCustomImages(),
		sysCalls:                 NewSystemCall(),
	}
}

func (c *Config) NewConfigsFromCobraAndLoadsCmdGlobalFlags(cmd *cobra.Command) IConfig {
	c.SetLogLevel(c.extractFlagValueString(cmd, "log-level", c.GetLogLevel()))
	c.SetConfigFilePath(c.extractFlagValueString(cmd, "config-file-path", c.GetConfigFilePath()))
	c.SetLogFilePath(c.extractFlagValueString(cmd, "log-file-path", c.GetLogFilePath()))
	return c
}

//nolint:lll,funlen // method need all configs
func (c *Config) NewConfigsFromCobraAndLoadsCmdStartFlags(cmd *cobra.Command) IConfig {
	c.SetMonitorRetryInSeconds(c.extractFlagValueInt64(cmd, "monitor-retry-count", c.GetMonitorRetryInSeconds()))
	c.SetPrintOutputType(c.extractFlagValueString(cmd, "output-format", c.GetPrintOutputType()))
	c.SetJSONOutputFilePath(c.extractFlagValueString(cmd, "json-output-file", c.GetJSONOutputFilePath()))
	c.SetSeveritiesToIgnore(c.extractFlagValueStringSlice(cmd, "ignore-severity", c.GetSeveritiesToIgnore()))
	c.SetFilesOrPathsToIgnore(c.extractFlagValueStringSlice(cmd, "ignore", c.GetFilesOrPathsToIgnore()))
	c.SetHorusecAPIURI(c.extractFlagValueString(cmd, "horusec-url", c.GetHorusecAPIUri()))
	c.SetTimeoutInSecondsRequest(c.extractFlagValueInt64(cmd, "request-timeout", c.GetTimeoutInSecondsRequest()))
	c.SetTimeoutInSecondsAnalysis(c.extractFlagValueInt64(cmd, "analysis-timeout", c.GetTimeoutInSecondsAnalysis()))
	c.SetRepositoryAuthorization(c.extractFlagValueString(cmd, "authorization", c.GetRepositoryAuthorization()))
	c.SetHeaders(c.extractFlagValueStringToString(cmd, "headers", c.GetHeaders()))
	c.SetReturnErrorIfFoundVulnerability(c.extractFlagValueBool(cmd, "return-error", c.GetReturnErrorIfFoundVulnerability()))
	c.SetProjectPath(c.extractFlagValueString(cmd, "project-path", c.GetProjectPath()))
	c.SetEnableGitHistoryAnalysis(c.extractFlagValueBool(cmd, "enable-git-history", c.GetEnableGitHistoryAnalysis()))
	c.SetCertInsecureSkipVerify(c.extractFlagValueBool(cmd, "insecure-skip-verify", c.GetCertInsecureSkipVerify()))
	c.SetCertPath(c.extractFlagValueString(cmd, "certificate-path", c.GetCertPath()))
	c.SetEnableCommitAuthor(c.extractFlagValueBool(cmd, "enable-commit-author", c.GetEnableCommitAuthor()))
	c.SetRepositoryName(c.extractFlagValueString(cmd, "repository-name", c.GetRepositoryName()))
	c.SetFalsePositiveHashes(c.extractFlagValueStringSlice(cmd, "false-positive", c.GetFalsePositiveHashes()))
	c.SetRiskAcceptHashes(c.extractFlagValueStringSlice(cmd, "risk-accept", c.GetRiskAcceptHashes()))
	c.SetContainerBindProjectPath(c.extractFlagValueString(cmd, "container-bind-project-path", c.GetContainerBindProjectPath()))
	c.SetDisableDocker(c.extractFlagValueBool(cmd, "disable-docker", c.GetDisableDocker()))
	c.SetCustomRulesPath(c.extractFlagValueString(cmd, "custom-rules-path", c.GetCustomRulesPath()))
	c.SetEnableInformationSeverity(c.extractFlagValueBool(cmd, "information-severity", c.GetEnableInformationSeverity()))
	c.SetShowVulnerabilitiesTypes(c.extractFlagValueStringSlice(cmd, "show-vulnerabilities-types", c.GetShowVulnerabilitiesTypes()))
	c.SetEnableOwaspDependencyCheck(c.extractFlagValueBool(cmd, "enable-owasp-dependency-check", c.GetDisableDocker()))
	return c
}

//nolint:funlen // method need all configs
func (c *Config) NewConfigsFromViper() IConfig {
	if existsViperConfig := c.setViperConfigsAndReturnIfExistFile(); !existsViperConfig {
		return c
	}
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
	c.SetWorkDir(viper.Get(c.toLowerCamel(EnvWorkDir)))
	c.SetEnableGitHistoryAnalysis(viper.GetBool(c.toLowerCamel(EnvEnableGitHistoryAnalysis)))
	c.SetCertInsecureSkipVerify(viper.GetBool(c.toLowerCamel(EnvCertInsecureSkipVerify)))
	c.SetCertPath(viper.GetString(c.toLowerCamel(EnvCertPath)))
	c.SetEnableCommitAuthor(viper.GetBool(c.toLowerCamel(EnvEnableCommitAuthor)))
	c.SetRepositoryName(viper.GetString(c.toLowerCamel(EnvRepositoryName)))
	c.SetFalsePositiveHashes(viper.GetStringSlice(c.toLowerCamel(EnvFalsePositiveHashes)))
	c.SetRiskAcceptHashes(viper.GetStringSlice(c.toLowerCamel(EnvRiskAcceptHashes)))
	c.SetHeaders(viper.GetStringMapString(c.toLowerCamel(EnvHeaders)))
	c.SetContainerBindProjectPath(viper.GetString(c.toLowerCamel(EnvContainerBindProjectPath)))
	c.SetToolsConfig(viper.Get(c.toLowerCamel(EnvToolsConfig)))
	c.SetDisableDocker(viper.GetBool(c.toLowerCamel(EnvDisableDocker)))
	c.SetCustomRulesPath(viper.GetString(c.toLowerCamel(EnvCustomRulesPath)))
	c.SetEnableInformationSeverity(viper.GetBool(c.toLowerCamel(EnvEnableInformationSeverity)))
	c.SetCustomImages(viper.Get(c.toLowerCamel(EnvCustomImages)))
	c.SetShowVulnerabilitiesTypes(viper.GetStringSlice(c.toLowerCamel(EnvShowVulnerabilitiesTypes)))
	c.SetEnableOwaspDependencyCheck(viper.GetBool(c.toLowerCamel(EnvEnableOwaspDependencyCheck)))
	c.SetLogFilePath(viper.GetString(EnvLogFilePath))
	return c
}

//nolint:lll,funlen // method need all configs
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
	c.SetEnableGitHistoryAnalysis(env.GetEnvOrDefaultBool(EnvEnableGitHistoryAnalysis, c.enableGitHistoryAnalysis))
	c.SetCertInsecureSkipVerify(env.GetEnvOrDefaultBool(EnvCertInsecureSkipVerify, c.certInsecureSkipVerify))
	c.SetCertPath(env.GetEnvOrDefault(EnvCertPath, c.certPath))
	c.SetEnableCommitAuthor(env.GetEnvOrDefaultBool(EnvEnableCommitAuthor, c.enableCommitAuthor))
	c.SetRepositoryName(env.GetEnvOrDefault(EnvRepositoryName, c.repositoryName))
	c.SetFalsePositiveHashes(c.factoryParseInputToSliceString(env.GetEnvOrDefaultInterface(EnvFalsePositiveHashes, c.falsePositiveHashes)))
	c.SetRiskAcceptHashes(c.factoryParseInputToSliceString(env.GetEnvOrDefaultInterface(EnvRiskAcceptHashes, c.riskAcceptHashes)))
	c.SetHeaders(env.GetEnvOrDefaultInterface(EnvHeaders, c.headers))
	c.SetContainerBindProjectPath(env.GetEnvOrDefault(EnvContainerBindProjectPath, c.containerBindProjectPath))
	c.SetDisableDocker(env.GetEnvOrDefaultBool(EnvDisableDocker, c.disableDocker))
	c.SetCustomRulesPath(env.GetEnvOrDefault(EnvCustomRulesPath, c.customRulesPath))
	c.SetEnableInformationSeverity(env.GetEnvOrDefaultBool(EnvEnableInformationSeverity, c.enableInformationSeverity))
	c.SetShowVulnerabilitiesTypes(c.factoryParseInputToSliceString(env.GetEnvOrDefaultInterface(EnvShowVulnerabilitiesTypes, c.showVulnerabilitiesTypes)))
	c.SetEnableOwaspDependencyCheck(env.GetEnvOrDefaultBool(EnvEnableOwaspDependencyCheck, c.enableOwaspDependencyCheck))
	c.SetLogFilePath(env.GetEnvOrDefault(EnvLogFilePath, c.logFilePath))
	return c
}

func (c *Config) GetDefaultConfigFilePath() string {
	currentDir, err := os.Getwd()
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorGetCurrentPath, err)
	}
	return path.Join(currentDir, "horusec-config.json")
}

func (c *Config) GetVersion() string {
	return "{{VERSION_NOT_FOUND}}"
}

func (c *Config) GetConfigFilePath() string {
	return valueordefault.GetStringValueOrDefault(c.configFilePath, c.GetDefaultConfigFilePath())
}

func (c *Config) SetConfigFilePath(configFilePath string) {
	c.configFilePath = configFilePath
}

func (c *Config) GetLogLevel() string {
	return valueordefault.GetStringValueOrDefault(c.logLevel, logrus.InfoLevel.String())
}
func (c *Config) SetLogLevel(logLevel string) {
	c.logLevel = logLevel
	logger.SetLogLevel(c.logLevel)
}
func (c *Config) SetLogFilePath(logFilePath string) {
	c.logFilePath = logFilePath
}

func (c *Config) SetLogOutput(writers ...io.Writer) error {
	file, err := c.getFile(c.logFilePath)
	if err != nil {
		return err
	}
	logger.LogSetOutput(append(writers, file)...)
	logger.LogInfo("Set log file to " + file.Name())
	return nil
}

func (c *Config) getFile(logPath string) (*os.File, error) {
	var err error
	if logPath == "" {
		logPath, err = c.sysCalls.Getwd()
		if err != nil {
			return nil, err
		}
	} else if _, err = c.sysCalls.Stat(logPath); c.sysCalls.IsNotExist(err) {
		return nil, err
	}
	return c.createLogFile(logPath)
}

func (c *Config) createLogFile(dir string) (*os.File, error) {
	dirPath := filepath.Join(dir, "tmp", "horusec")
	if _, err := c.sysCalls.Stat(dirPath); c.sysCalls.IsNotExist(err) {
		err := c.sysCalls.MkdirAll(dirPath, os.ModePerm)
		if err != nil {
			return nil, err
		}
	}
	fileName := filepath.Join(dirPath, "horusec-log-"+time.Now().Format("2006-01-02 15:04:05")+".log")
	return c.sysCalls.Create(fileName)
}

func (c *Config) GetLogFilePath() string {
	return valueordefault.GetStringValueOrDefault(c.logFilePath, "")
}

func (c *Config) GetHorusecAPIUri() string {
	return valueordefault.GetStringValueOrDefault(c.horusecAPIUri, "http://0.0.0.0:8000")
}

func (c *Config) SetHorusecAPIURI(horusecAPIURI string) {
	c.horusecAPIUri = horusecAPIURI
}

func (c *Config) GetTimeoutInSecondsRequest() int64 {
	const defaultValue = 300
	return valueordefault.GetInt64ValueOrDefault(c.timeoutInSecondsRequest, int64(defaultValue))
}

func (c *Config) SetTimeoutInSecondsRequest(timeoutInSecondsRequest int64) {
	c.timeoutInSecondsRequest = timeoutInSecondsRequest
}

func (c *Config) GetTimeoutInSecondsAnalysis() int64 {
	const defaultValue = 600
	return valueordefault.GetInt64ValueOrDefault(c.timeoutInSecondsAnalysis, int64(defaultValue))
}

func (c *Config) SetTimeoutInSecondsAnalysis(timeoutInSecondsAnalysis int64) {
	c.timeoutInSecondsAnalysis = timeoutInSecondsAnalysis
}

func (c *Config) GetMonitorRetryInSeconds() int64 {
	const defaultValue = 15
	return valueordefault.GetInt64ValueOrDefault(c.monitorRetryInSeconds, int64(defaultValue))
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
	return valueordefault.GetSliceStringValueOrDefault(c.severitiesToIgnore, []string{"INFO"})
}

func (c *Config) SetSeveritiesToIgnore(severitiesToIgnore []string) {
	c.severitiesToIgnore = c.factoryParseInputToSliceString(severitiesToIgnore)
}

func (c *Config) GetFilesOrPathsToIgnore() []string {
	return valueordefault.GetSliceStringValueOrDefault(c.filesOrPathsToIgnore, []string{"*tmp*", "**/.vscode/**"})
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

func (c *Config) GetWorkDir() *workdir.WorkDir {
	return valueordefault.GetInterfaceValueOrDefault(c.workDir, workdir.NewWorkDir()).(*workdir.WorkDir)
}

func (c *Config) SetWorkDir(input interface{}) {
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
	if repositoryName := valueordefault.GetStringValueOrDefault(c.repositoryName, ""); repositoryName != "" {
		return repositoryName
	}

	return filepath.Base(c.GetProjectPath())
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

func (c *Config) GetHeaders() (headers map[string]string) {
	return valueordefault.GetMapStringStringValueOrDefault(c.headers, map[string]string{})
}

func (c *Config) SetHeaders(headers interface{}) {
	output, err := utilsJson.ConvertInterfaceToMapString(headers)
	logger.LogErrorWithLevel(messages.MsgErrorSetHeadersOnConfig, err)
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

func (c *Config) GetToolsConfig() toolsconfig.MapToolConfig {
	content := toolsconfig.ToolsConfigsStruct{}
	return valueordefault.GetInterfaceValueOrDefault(
		c.toolsConfig, content.ToMap()).(toolsconfig.MapToolConfig)
}

func (c *Config) SetToolsConfig(toolsConfig interface{}) {
	c.toolsConfig = toolsconfig.ParseInterfaceToMapToolsConfig(toolsConfig)
}

func (c *Config) IsEmptyRepositoryAuthorization() bool {
	return c.repositoryAuthorization == "" || c.repositoryAuthorization == uuid.Nil.String()
}

func (c *Config) extractFlagValueString(cmd *cobra.Command, name, defaultValue string) string {
	if cmd.PersistentFlags().Changed(name) {
		flagValue, err := cmd.PersistentFlags().GetString(name)
		logger.LogPanicWithLevel(messages.MsgPanicGetFlagValue, err)
		return flagValue
	}
	return defaultValue
}

func (c *Config) extractFlagValueInt64(cmd *cobra.Command, name string, defaultValue int64) int64 {
	if cmd.PersistentFlags().Changed(name) {
		flagValue, err := cmd.PersistentFlags().GetInt64(name)
		logger.LogPanicWithLevel(messages.MsgPanicGetFlagValue, err)
		return flagValue
	}
	return defaultValue
}

func (c *Config) extractFlagValueBool(cmd *cobra.Command, name string, defaultValue bool) bool {
	if cmd.PersistentFlags().Changed(name) {
		flagValue, err := cmd.PersistentFlags().GetBool(name)
		logger.LogPanicWithLevel(messages.MsgPanicGetFlagValue, err)
		return flagValue
	}
	return defaultValue
}

func (c *Config) extractFlagValueStringSlice(cmd *cobra.Command, name string, defaultValue []string) []string {
	if cmd.PersistentFlags().Changed(name) {
		flagValue, err := cmd.PersistentFlags().GetStringSlice(name)
		logger.LogPanicWithLevel(messages.MsgPanicGetFlagValue, err)
		return flagValue
	}
	return defaultValue
}

func (c *Config) extractFlagValueStringToString(
	cmd *cobra.Command, name string, defaultValue map[string]string) map[string]string {
	if cmd.PersistentFlags().Changed(name) {
		flagValue, err := cmd.PersistentFlags().GetStringToString(name)
		logger.LogPanicWithLevel(messages.MsgPanicGetFlagValue, err)
		return flagValue
	}
	return defaultValue
}

func (c *Config) setViperConfigsAndReturnIfExistFile() bool {
	logger.LogDebugWithLevel(messages.MsgDebugConfigFileRunningOnPath + c.GetConfigFilePath())
	if _, err := os.Stat(c.GetConfigFilePath()); os.IsNotExist(err) {
		logger.LogDebugWithLevel(messages.MsgDebugConfigFileNotFoundOnPath)
		return false
	}
	viper.SetConfigFile(c.GetConfigFilePath())
	logger.LogPanicWithLevel(messages.MsgPanicGetConfigFilePath, viper.ReadInConfig())
	return true
}

//nolint // parse struct is necessary > 15 lines
func (c *Config) toMap() map[string]interface{} {
	return map[string]interface{}{
		"configFilePath":                  c.configFilePath,
		"horusecAPIUri":                   c.horusecAPIUri,
		"repositoryAuthorization":         c.repositoryAuthorization,
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
		"headers":                         c.headers,
		"toolsConfig":                     c.toolsConfig,
		"workDir":                         c.workDir,
		"disableDocker":                   c.disableDocker,
		"customRulesPath":                 c.customRulesPath,
		"enableInformationSeverity":       c.enableInformationSeverity,
		"customImages":                    c.customImages,
		"showVulnerabilitiesTypes":        c.showVulnerabilitiesTypes,
		"enableOwaspDependencyCheck":      c.enableOwaspDependencyCheck,
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

// nolint:funlen // is necessary to return completely map
func (c *Config) ToMapLowerCase() map[string]interface{} {
	return map[string]interface{}{
		c.toLowerCamel(EnvHorusecAPIUri):                   c.GetHorusecAPIUri(),
		c.toLowerCamel(EnvTimeoutInSecondsRequest):         c.GetTimeoutInSecondsRequest(),
		c.toLowerCamel(EnvTimeoutInSecondsAnalysis):        c.GetTimeoutInSecondsAnalysis(),
		c.toLowerCamel(EnvMonitorRetryInSeconds):           c.GetMonitorRetryInSeconds(),
		c.toLowerCamel(EnvRepositoryAuthorization):         c.GetRepositoryAuthorization(),
		c.toLowerCamel(EnvPrintOutputType):                 c.GetPrintOutputType(),
		c.toLowerCamel(EnvJSONOutputFilePath):              c.GetJSONOutputFilePath(),
		c.toLowerCamel(EnvSeveritiesToIgnore):              c.GetSeveritiesToIgnore(),
		c.toLowerCamel(EnvFilesOrPathsToIgnore):            c.GetFilesOrPathsToIgnore(),
		c.toLowerCamel(EnvReturnErrorIfFoundVulnerability): c.GetReturnErrorIfFoundVulnerability(),
		c.toLowerCamel(EnvProjectPath):                     c.GetProjectPath(),
		c.toLowerCamel(EnvWorkDir):                         c.GetWorkDir(),
		c.toLowerCamel(EnvEnableGitHistoryAnalysis):        c.GetEnableGitHistoryAnalysis(),
		c.toLowerCamel(EnvCertInsecureSkipVerify):          c.GetCertInsecureSkipVerify(),
		c.toLowerCamel(EnvCertPath):                        c.GetCertPath(),
		c.toLowerCamel(EnvEnableCommitAuthor):              c.GetEnableCommitAuthor(),
		c.toLowerCamel(EnvRepositoryName):                  c.GetRepositoryName(),
		c.toLowerCamel(EnvFalsePositiveHashes):             c.GetFalsePositiveHashes(),
		c.toLowerCamel(EnvRiskAcceptHashes):                c.GetRiskAcceptHashes(),
		c.toLowerCamel(EnvHeaders):                         c.GetHeaders(),
		c.toLowerCamel(EnvContainerBindProjectPath):        c.GetContainerBindProjectPath(),
		c.toLowerCamel(EnvToolsConfig):                     c.GetToolsConfig(),
		c.toLowerCamel(EnvDisableDocker):                   c.GetDisableDocker(),
		c.toLowerCamel(EnvCustomRulesPath):                 c.GetCustomRulesPath(),
		c.toLowerCamel(EnvEnableInformationSeverity):       c.GetEnableInformationSeverity(),
		c.toLowerCamel(EnvCustomImages):                    c.GetCustomImages(),
		c.toLowerCamel(EnvShowVulnerabilitiesTypes):        c.GetShowVulnerabilitiesTypes(),
		c.toLowerCamel(EnvEnableOwaspDependencyCheck):      c.GetEnableOwaspDependencyCheck(),
		c.toLowerCamel(EnvLogFilePath):                     c.GetLogFilePath(),
	}
}

func (c *Config) NormalizeConfigs() IConfig {
	if c.GetJSONOutputFilePath() != "" {
		absJSONOutputFilePath, _ := filepath.Abs(c.GetJSONOutputFilePath())
		c.SetJSONOutputFilePath(absJSONOutputFilePath)
	}
	projectPath, _ := filepath.Abs(c.GetProjectPath())
	c.SetProjectPath(projectPath)
	configFilePath, _ := filepath.Abs(c.GetConfigFilePath())
	c.SetConfigFilePath(configFilePath)
	logFilePath, _ := filepath.Abs(c.GetLogFilePath())
	c.SetLogFilePath(logFilePath)
	return c
}

func (c *Config) toLowerCamel(value string) string {
	return strcase.ToLowerCamel(strcase.ToSnake(value))
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

func (c *Config) replaceCommaToSpaceString(input string) []string {
	var response []string
	if input != "" {
		for _, item := range strings.Split(strings.TrimSpace(input), ",") {
			newItem := strings.ReplaceAll(strings.TrimSpace(item), ",", "")
			response = append(response, newItem)
		}
	}
	return response
}

func (c *Config) replaceCommaToSpaceSliceString(input []string) []string {
	var response []string
	for _, item := range input {
		newItem := strings.ReplaceAll(strings.TrimSpace(item), ",", "")
		response = append(response, newItem)
	}
	return response
}

func (c *Config) GetDisableDocker() bool {
	return dist.IsStandAlone() || c.disableDocker
}

func (c *Config) SetDisableDocker(disableDocker bool) {
	c.disableDocker = disableDocker
}

func (c *Config) GetCustomRulesPath() string {
	return c.customRulesPath
}

func (c *Config) SetCustomRulesPath(customRulesPath string) {
	c.customRulesPath = customRulesPath
}

func (c *Config) GetEnableInformationSeverity() bool {
	return c.enableInformationSeverity
}

func (c *Config) SetEnableInformationSeverity(enableInformationSeverity bool) {
	c.enableInformationSeverity = enableInformationSeverity
}

func (c *Config) GetCustomImages() customImages.CustomImages {
	return c.customImages
}

func (c *Config) SetShowVulnerabilitiesTypes(vulnerabilitiesTypes []string) {
	c.showVulnerabilitiesTypes = c.factoryParseInputToSliceString(vulnerabilitiesTypes)
}

func (c *Config) GetShowVulnerabilitiesTypes() []string {
	return valueordefault.GetSliceStringValueOrDefault(c.showVulnerabilitiesTypes, []string{
		enumsVulnerability.Vulnerability.ToString(),
	})
}

func (c *Config) SetCustomImages(configData interface{}) {
	customImg := customImages.CustomImages{}

	bytes, err := json.Marshal(configData)
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorWhileParsingCustomImages, err)
	}

	if err := json.Unmarshal(bytes, &customImg); err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorWhileParsingCustomImages, err)
	}

	c.customImages = customImg
}

func (c *Config) GetEnableOwaspDependencyCheck() bool {
	return c.enableOwaspDependencyCheck
}

func (c *Config) SetEnableOwaspDependencyCheck(enableOwaspDependencyCheck bool) {
	c.enableOwaspDependencyCheck = enableOwaspDependencyCheck
}
func (c *Config) SetSystemCall(calls ISystemCalls) {
	c.sysCalls = calls
}
