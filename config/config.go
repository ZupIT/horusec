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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/ZupIT/horusec-devkit/pkg/enums/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/utils/env"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	customimages "github.com/ZupIT/horusec/internal/entities/custom_images"
	"github.com/ZupIT/horusec/internal/helpers/messages"

	"github.com/google/uuid"
	"github.com/iancoleman/strcase"
	"github.com/sirupsen/logrus"

	"github.com/ZupIT/horusec/config/dist"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/entities/workdir"
	jsonutils "github.com/ZupIT/horusec/internal/utils/json"
	"github.com/ZupIT/horusec/internal/utils/valueordefault"
)

var version = "{{VERSION_NOT_FOUND}}"

const (
	EnvHorusecAPIUri                   = "HORUSEC_CLI_HORUSEC_API_URI"
	EnvTimeoutInSecondsRequest         = "HORUSEC_CLI_TIMEOUT_IN_SECONDS_REQUEST"
	EnvTimeoutInSecondsAnalysis        = "HORUSEC_CLI_TIMEOUT_IN_SECONDS_ANALYSIS"
	EnvMonitorRetryInSeconds           = "HORUSEC_CLI_MONITOR_RETRY_IN_SECONDS"
	EnvRepositoryAuthorization         = "HORUSEC_CLI_REPOSITORY_AUTHORIZATION"
	EnvPrintOutputType                 = "HORUSEC_CLI_PRINT_OUTPUT_TYPE"
	EnvJSONOutputFilePath              = "HORUSEC_CLI_JSON_OUTPUT_FILEPATH"
	EnvSeveritiesToIgnore              = "HORUSEC_CLI_SEVERITIES_TO_IGNORE"
	EnvFilesOrPathsToIgnore            = "HORUSEC_CLI_FILES_OR_PATHS_TO_IGNORE"
	EnvReturnErrorIfFoundVulnerability = "HORUSEC_CLI_RETURN_ERROR_IF_FOUND_VULNERABILITY"
	EnvProjectPath                     = "HORUSEC_CLI_PROJECT_PATH"
	EnvWorkDir                         = "HORUSEC_CLI_WORK_DIR"
	EnvEnableGitHistoryAnalysis        = "HORUSEC_CLI_ENABLE_GIT_HISTORY_ANALYSIS"
	EnvCertInsecureSkipVerify          = "HORUSEC_CLI_CERT_INSECURE_SKIP_VERIFY"
	EnvCertPath                        = "HORUSEC_CLI_CERT_PATH"
	EnvEnableCommitAuthor              = "HORUSEC_CLI_ENABLE_COMMIT_AUTHOR"
	EnvRepositoryName                  = "HORUSEC_CLI_REPOSITORY_NAME"
	EnvFalsePositiveHashes             = "HORUSEC_CLI_FALSE_POSITIVE_HASHES"
	EnvRiskAcceptHashes                = "HORUSEC_CLI_RISK_ACCEPT_HASHES"
	EnvToolsConfig                     = "HORUSEC_CLI_TOOLS_CONFIG"
	EnvHeaders                         = "HORUSEC_CLI_HEADERS"
	EnvContainerBindProjectPath        = "HORUSEC_CLI_CONTAINER_BIND_PROJECT_PATH"
	EnvDisableDocker                   = "HORUSEC_CLI_DISABLE_DOCKER"
	EnvCustomRulesPath                 = "HORUSEC_CLI_CUSTOM_RULES_PATH"
	EnvEnableInformationSeverity       = "HORUSEC_CLI_ENABLE_INFORMATION_SEVERITY"
	EnvCustomImages                    = "HORUSEC_CLI_CUSTOM_IMAGES"
	EnvShowVulnerabilitiesTypes        = "HORUSEC_CLI_SHOW_VULNERABILITIES_TYPES"
	EnvLogFilePath                     = "HORUSEC_CLI_LOG_FILE_PATH"
	EnvEnableOwaspDependencyCheck      = "HORUSEC_CLI_ENABLE_OWASP_DEPENDENCY_CHECK"
	EnvEnableShellCheck                = "HORUSEC_CLI_ENABLE_SHELLCHECK"
)

type GlobalOptions struct {
	// TODO: Remove this field.
	// IsTimeout is not a configuration value.
	// IsTimeout just exists to communicate that analysis
	// execed the timeout configuration.
	// We should find a better way to handle this.
	IsTimeout      bool   `json:"is_timeout"`
	LogLevel       string `json:"log_level"`
	ConfigFilePath string `json:"config_file_path"`
	LogFilePath    string `json:"log_file_path"`
}

type StartOptions struct {
	HorusecAPIUri                   string                    `json:"horusec_api_uri"`
	RepositoryAuthorization         string                    `json:"repository_authorization"`
	CertPath                        string                    `json:"cert_path"`
	RepositoryName                  string                    `json:"repository_name"`
	PrintOutputType                 string                    `json:"print_output_type"`
	JSONOutputFilePath              string                    `json:"json_output_file_path"`
	ProjectPath                     string                    `json:"project_path"`
	CustomRulesPath                 string                    `json:"custom_rules_path"`
	ContainerBindProjectPath        string                    `json:"container_bind_project_path"`
	TimeoutInSecondsRequest         int64                     `json:"timeout_in_seconds_request"`
	TimeoutInSecondsAnalysis        int64                     `json:"timeout_in_seconds_analysis"`
	MonitorRetryInSeconds           int64                     `json:"monitor_retry_in_seconds"`
	ReturnErrorIfFoundVulnerability bool                      `json:"return_error_if_found_vulnerability"`
	EnableGitHistoryAnalysis        bool                      `json:"enable_git_history_analysis"`
	CertInsecureSkipVerify          bool                      `json:"cert_insecure_skip_verify"`
	EnableCommitAuthor              bool                      `json:"enable_commit_author"`
	DisableDocker                   bool                      `json:"disable_docker"`
	EnableInformationSeverity       bool                      `json:"enable_information_severity"`
	EnableOwaspDependencyCheck      bool                      `json:"enable_owasp_dependency_check"`
	EnableShellCheck                bool                      `json:"enable_shell_check"`
	SeveritiesToIgnore              []string                  `json:"severities_to_ignore"`
	FilesOrPathsToIgnore            []string                  `json:"files_or_paths_to_ignore"`
	FalsePositiveHashes             []string                  `json:"false_positive_hashes"`
	RiskAcceptHashes                []string                  `json:"risk_accept_hashes"`
	ShowVulnerabilitiesTypes        []string                  `json:"show_vulnerabilities_types"`
	ToolsConfig                     toolsconfig.MapToolConfig `json:"tools_config"`
	Headers                         map[string]string         `json:"headers"`
	WorkDir                         *workdir.WorkDir          `json:"work_dir"`
	CustomImages                    customimages.CustomImages `json:"custom_images"`
}

type Config struct {
	GlobalOptions
	StartOptions
	Version string `json:"version"`
}

// New creates a new default config
//
// nolint:funlen
func New() *Config {
	wd, err := os.Getwd()
	if err != nil {
		logger.LogWarn("Error to get current working directory: %v", err)
	}

	return &Config{
		Version: version,
		GlobalOptions: GlobalOptions{
			ConfigFilePath: filepath.Join(wd, "horusec-config.json"),
			LogLevel:       logrus.InfoLevel.String(),
			LogFilePath: filepath.Join(
				os.TempDir(), fmt.Sprintf("horusec-log-%s.log", time.Now().Format("2006-01-02 15:04:05")),
			),
			IsTimeout: false,
		},
		StartOptions: StartOptions{
			HorusecAPIUri:                   "http://0.0.0.0:8000",
			TimeoutInSecondsRequest:         300,
			TimeoutInSecondsAnalysis:        600,
			MonitorRetryInSeconds:           15,
			RepositoryAuthorization:         uuid.Nil.String(),
			PrintOutputType:                 "",
			JSONOutputFilePath:              "",
			SeveritiesToIgnore:              []string{"INFO"},
			FilesOrPathsToIgnore:            []string{"*tmp*", "**/.vscode/**"},
			ReturnErrorIfFoundVulnerability: false,
			ProjectPath:                     wd,
			WorkDir:                         workdir.NewWorkDir(),
			EnableGitHistoryAnalysis:        false,
			CertInsecureSkipVerify:          false,
			CertPath:                        "",
			EnableCommitAuthor:              false,
			RepositoryName:                  filepath.Base(wd),
			RiskAcceptHashes:                make([]string, 0),
			FalsePositiveHashes:             make([]string, 0),
			Headers:                         make(map[string]string),
			ContainerBindProjectPath:        "",
			ToolsConfig:                     toolsconfig.ParseInterfaceToMapToolsConfig(toolsconfig.ToolConfig{}),
			ShowVulnerabilitiesTypes:        []string{vulnerability.Vulnerability.ToString()},
			CustomImages:                    customimages.NewCustomImages(),
			DisableDocker:                   dist.IsStandAlone(),
			CustomRulesPath:                 "",
			EnableInformationSeverity:       false,
			EnableOwaspDependencyCheck:      false,
			EnableShellCheck:                false,
		},
	}
}

// MergeFromConfigFile merge current instance of config with values
// configured on configuration file.
//
// The config file path used here is the default or the value used in
// command line args.
//
//nolint:funlen,gocyclo
func (c *Config) MergeFromConfigFile() *Config {
	if !c.setViperConfigsAndReturnIfExistFile() {
		return c
	}
	c.HorusecAPIUri = valueordefault.GetStringValueOrDefault(
		viper.GetString(c.toLowerCamel(EnvHorusecAPIUri)), c.HorusecAPIUri,
	)
	c.TimeoutInSecondsRequest = valueordefault.GetInt64ValueOrDefault(
		viper.GetInt64(c.toLowerCamel(EnvTimeoutInSecondsRequest)), c.TimeoutInSecondsRequest,
	)
	c.TimeoutInSecondsAnalysis = valueordefault.GetInt64ValueOrDefault(
		viper.GetInt64(c.toLowerCamel(EnvTimeoutInSecondsAnalysis)), c.TimeoutInSecondsAnalysis,
	)
	c.MonitorRetryInSeconds = valueordefault.GetInt64ValueOrDefault(
		viper.GetInt64(c.toLowerCamel(EnvMonitorRetryInSeconds)), c.MonitorRetryInSeconds,
	)
	c.RepositoryAuthorization = valueordefault.GetStringValueOrDefault(
		viper.GetString(c.toLowerCamel(EnvRepositoryAuthorization)), c.RepositoryAuthorization,
	)
	c.PrintOutputType = valueordefault.GetStringValueOrDefault(
		viper.GetString(c.toLowerCamel(EnvPrintOutputType)), c.PrintOutputType,
	)
	c.JSONOutputFilePath = valueordefault.GetStringValueOrDefault(
		viper.GetString(c.toLowerCamel(EnvJSONOutputFilePath)), c.JSONOutputFilePath,
	)
	c.SeveritiesToIgnore = valueordefault.GetSliceStringValueOrDefault(
		viper.GetStringSlice(c.toLowerCamel(EnvSeveritiesToIgnore)), c.SeveritiesToIgnore,
	)
	c.FilesOrPathsToIgnore = valueordefault.GetSliceStringValueOrDefault(
		viper.GetStringSlice(c.toLowerCamel(EnvFilesOrPathsToIgnore)), c.FilesOrPathsToIgnore,
	)
	c.ReturnErrorIfFoundVulnerability = viper.GetBool(c.toLowerCamel(EnvReturnErrorIfFoundVulnerability))
	c.ProjectPath = valueordefault.GetStringValueOrDefault(
		viper.GetString(c.toLowerCamel(EnvProjectPath)), c.ProjectPath,
	)

	if wd := viper.Get(c.toLowerCamel(EnvWorkDir)); wd != nil {
		c.WorkDir = c.WorkDir.ParseInterfaceToStruct(wd)
	}

	c.EnableGitHistoryAnalysis = viper.GetBool(c.toLowerCamel(EnvEnableGitHistoryAnalysis))
	c.CertInsecureSkipVerify = viper.GetBool(c.toLowerCamel(EnvCertInsecureSkipVerify))
	c.CertPath = valueordefault.GetStringValueOrDefault(
		viper.GetString(c.toLowerCamel(EnvCertPath)), c.CertPath,
	)

	c.EnableCommitAuthor = viper.GetBool(c.toLowerCamel(EnvEnableCommitAuthor))

	c.RepositoryName = valueordefault.GetStringValueOrDefault(
		viper.GetString(c.toLowerCamel(EnvRepositoryName)), c.RepositoryName,
	)

	c.FalsePositiveHashes = valueordefault.GetSliceStringValueOrDefault(
		viper.GetStringSlice(c.toLowerCamel(EnvFalsePositiveHashes)), c.FalsePositiveHashes,
	)

	c.RiskAcceptHashes = valueordefault.GetSliceStringValueOrDefault(
		viper.GetStringSlice(c.toLowerCamel(EnvRiskAcceptHashes)), c.RiskAcceptHashes,
	)

	c.Headers = viper.GetStringMapString(c.toLowerCamel(EnvHeaders))
	c.ContainerBindProjectPath = valueordefault.GetStringValueOrDefault(
		viper.GetString(c.toLowerCamel(EnvContainerBindProjectPath)), c.ContainerBindProjectPath,
	)

	if cfg := viper.Get(c.toLowerCamel(EnvToolsConfig)); cfg != nil {
		c.ToolsConfig = toolsconfig.ParseInterfaceToMapToolsConfig(cfg)
	}

	c.DisableDocker = viper.GetBool(c.toLowerCamel(EnvDisableDocker))
	c.CustomRulesPath = valueordefault.GetStringValueOrDefault(
		viper.GetString(c.toLowerCamel(EnvCustomRulesPath)), c.CustomRulesPath,
	)
	c.EnableInformationSeverity = viper.GetBool(c.toLowerCamel(EnvEnableInformationSeverity))

	if images := viper.Get(c.toLowerCamel(EnvCustomImages)); images != nil {
		customImg := customimages.CustomImages{}
		bytes, err := json.Marshal(images)
		if err != nil {
			logger.LogErrorWithLevel(messages.MsgErrorWhileParsingCustomImages, err)
		}
		if err := json.Unmarshal(bytes, &customImg); err != nil {
			logger.LogErrorWithLevel(messages.MsgErrorWhileParsingCustomImages, err)
		}
		c.CustomImages = customImg
	}

	c.ShowVulnerabilitiesTypes = valueordefault.GetSliceStringValueOrDefault(
		viper.GetStringSlice(c.toLowerCamel(EnvShowVulnerabilitiesTypes)), c.ShowVulnerabilitiesTypes,
	)
	c.LogFilePath = valueordefault.GetStringValueOrDefault(
		viper.GetString(c.toLowerCamel(EnvLogFilePath)), c.LogFilePath,
	)
	c.EnableOwaspDependencyCheck = viper.GetBool(c.toLowerCamel(EnvEnableOwaspDependencyCheck))
	c.EnableShellCheck = viper.GetBool(c.toLowerCamel(EnvEnableShellCheck))
	return c
}

// MergeFromEnvironmentVariables merge current instance of config with values
// configured on environment variables.
//
//nolint:lll,funlen
func (c *Config) MergeFromEnvironmentVariables() *Config {
	c.HorusecAPIUri = env.GetEnvOrDefault(EnvHorusecAPIUri, c.HorusecAPIUri)
	c.TimeoutInSecondsRequest = env.GetEnvOrDefaultInt64(EnvTimeoutInSecondsRequest, c.TimeoutInSecondsRequest)
	c.TimeoutInSecondsAnalysis = env.GetEnvOrDefaultInt64(EnvTimeoutInSecondsAnalysis, c.TimeoutInSecondsAnalysis)
	c.MonitorRetryInSeconds = env.GetEnvOrDefaultInt64(EnvMonitorRetryInSeconds, c.MonitorRetryInSeconds)
	c.RepositoryAuthorization = env.GetEnvOrDefault(EnvRepositoryAuthorization, c.RepositoryAuthorization)
	c.PrintOutputType = env.GetEnvOrDefault(EnvPrintOutputType, c.PrintOutputType)
	c.JSONOutputFilePath = env.GetEnvOrDefault(EnvJSONOutputFilePath, c.JSONOutputFilePath)

	c.SeveritiesToIgnore = c.factoryParseInputToSliceString(env.GetEnvOrDefaultInterface(EnvSeveritiesToIgnore, c.SeveritiesToIgnore))

	c.FilesOrPathsToIgnore = c.factoryParseInputToSliceString(env.GetEnvOrDefaultInterface(EnvFilesOrPathsToIgnore, c.FilesOrPathsToIgnore))

	c.ReturnErrorIfFoundVulnerability = env.GetEnvOrDefaultBool(EnvReturnErrorIfFoundVulnerability, c.ReturnErrorIfFoundVulnerability)
	c.ProjectPath = env.GetEnvOrDefault(EnvProjectPath, c.ProjectPath)
	c.EnableGitHistoryAnalysis = env.GetEnvOrDefaultBool(EnvEnableGitHistoryAnalysis, c.EnableGitHistoryAnalysis)
	c.CertInsecureSkipVerify = env.GetEnvOrDefaultBool(EnvCertInsecureSkipVerify, c.CertInsecureSkipVerify)
	c.CertPath = env.GetEnvOrDefault(EnvCertPath, c.CertPath)
	c.EnableCommitAuthor = env.GetEnvOrDefaultBool(EnvEnableCommitAuthor, c.EnableCommitAuthor)
	c.RepositoryName = env.GetEnvOrDefault(EnvRepositoryName, c.RepositoryName)

	c.FalsePositiveHashes = c.factoryParseInputToSliceString(env.GetEnvOrDefaultInterface(EnvFalsePositiveHashes, c.FalsePositiveHashes))

	c.RiskAcceptHashes = c.factoryParseInputToSliceString(env.GetEnvOrDefaultInterface(EnvRiskAcceptHashes, c.RiskAcceptHashes))

	if v := env.GetEnvOrDefaultInterface(EnvHeaders, c.Headers); v != nil {
		headers, err := jsonutils.ConvertInterfaceToMapString(v)
		logger.LogErrorWithLevel(messages.MsgErrorSetHeadersOnConfig, err)
		c.Headers = headers
	}

	c.ContainerBindProjectPath = env.GetEnvOrDefault(EnvContainerBindProjectPath, c.ContainerBindProjectPath)
	c.DisableDocker = env.GetEnvOrDefaultBool(EnvDisableDocker, c.DisableDocker)
	c.CustomRulesPath = env.GetEnvOrDefault(EnvCustomRulesPath, c.CustomRulesPath)
	c.EnableInformationSeverity = env.GetEnvOrDefaultBool(EnvEnableInformationSeverity, c.EnableInformationSeverity)

	c.ShowVulnerabilitiesTypes = c.factoryParseInputToSliceString(env.GetEnvOrDefaultInterface(EnvShowVulnerabilitiesTypes, c.ShowVulnerabilitiesTypes))

	c.LogFilePath = env.GetEnvOrDefault(EnvLogFilePath, c.LogFilePath)
	c.EnableOwaspDependencyCheck = env.GetEnvOrDefaultBool(EnvEnableOwaspDependencyCheck, c.EnableOwaspDependencyCheck)
	c.EnableShellCheck = env.GetEnvOrDefaultBool(EnvEnableShellCheck, c.EnableShellCheck)
	return c
}

// PreRun is a hook that normalize config values and create the log file.
// This hook is used as a PreRun on cobra commands.
func (c *Config) PreRun(_ *cobra.Command, _ []string) error {
	return c.Normalize().configureLogger()
}

// configureLogger create the log file and configure the log output.
func (c *Config) configureLogger() error {
	log, err := os.OpenFile(c.LogFilePath, os.O_CREATE|os.O_RDWR, os.ModePerm)
	if err != nil {
		return err
	}
	logger.LogSetOutput(log, os.Stdout)
	logger.LogDebugWithLevel("Set log file to " + log.Name())
	return nil
}

func (c *Config) IsEmptyRepositoryAuthorization() bool {
	return c.RepositoryAuthorization == "" || c.RepositoryAuthorization == uuid.Nil.String()
}

func (c *Config) setViperConfigsAndReturnIfExistFile() bool {
	logger.LogDebugWithLevel(messages.MsgDebugConfigFileRunningOnPath + c.ConfigFilePath)
	if _, err := os.Stat(c.ConfigFilePath); os.IsNotExist(err) {
		logger.LogDebugWithLevel(messages.MsgDebugConfigFileNotFoundOnPath)
		return false
	}
	viper.SetConfigFile(c.ConfigFilePath)
	logger.LogPanicWithLevel(messages.MsgPanicGetConfigFilePath, viper.ReadInConfig())
	return true
}

func (c *Config) ToBytes(_ bool) []byte {
	bytes, _ := json.MarshalIndent(c, "", "  ")
	return bytes
}

// nolint:funlen // is necessary to return completely map
func (c *Config) ToMapLowerCase() map[string]interface{} {
	return map[string]interface{}{
		c.toLowerCamel(EnvHorusecAPIUri):                   c.HorusecAPIUri,
		c.toLowerCamel(EnvTimeoutInSecondsRequest):         c.TimeoutInSecondsRequest,
		c.toLowerCamel(EnvTimeoutInSecondsAnalysis):        c.TimeoutInSecondsAnalysis,
		c.toLowerCamel(EnvMonitorRetryInSeconds):           c.MonitorRetryInSeconds,
		c.toLowerCamel(EnvRepositoryAuthorization):         c.RepositoryAuthorization,
		c.toLowerCamel(EnvPrintOutputType):                 c.PrintOutputType,
		c.toLowerCamel(EnvJSONOutputFilePath):              c.JSONOutputFilePath,
		c.toLowerCamel(EnvSeveritiesToIgnore):              c.SeveritiesToIgnore,
		c.toLowerCamel(EnvFilesOrPathsToIgnore):            c.FilesOrPathsToIgnore,
		c.toLowerCamel(EnvReturnErrorIfFoundVulnerability): c.ReturnErrorIfFoundVulnerability,
		c.toLowerCamel(EnvProjectPath):                     c.ProjectPath,
		c.toLowerCamel(EnvWorkDir):                         c.WorkDir,
		c.toLowerCamel(EnvEnableGitHistoryAnalysis):        c.EnableGitHistoryAnalysis,
		c.toLowerCamel(EnvCertInsecureSkipVerify):          c.CertInsecureSkipVerify,
		c.toLowerCamel(EnvCertPath):                        c.CertPath,
		c.toLowerCamel(EnvEnableCommitAuthor):              c.EnableCommitAuthor,
		c.toLowerCamel(EnvRepositoryName):                  c.RepositoryName,
		c.toLowerCamel(EnvFalsePositiveHashes):             c.FalsePositiveHashes,
		c.toLowerCamel(EnvRiskAcceptHashes):                c.RiskAcceptHashes,
		c.toLowerCamel(EnvHeaders):                         c.Headers,
		c.toLowerCamel(EnvContainerBindProjectPath):        c.ContainerBindProjectPath,
		c.toLowerCamel(EnvToolsConfig):                     c.ToolsConfig,
		c.toLowerCamel(EnvDisableDocker):                   c.DisableDocker,
		c.toLowerCamel(EnvCustomRulesPath):                 c.CustomRulesPath,
		c.toLowerCamel(EnvEnableInformationSeverity):       c.EnableInformationSeverity,
		c.toLowerCamel(EnvCustomImages):                    c.CustomImages,
		c.toLowerCamel(EnvShowVulnerabilitiesTypes):        c.ShowVulnerabilitiesTypes,
		c.toLowerCamel(EnvLogFilePath):                     c.LogFilePath,
		c.toLowerCamel(EnvEnableOwaspDependencyCheck):      c.EnableOwaspDependencyCheck,
		c.toLowerCamel(EnvEnableShellCheck):                c.EnableShellCheck,
	}
}

// Normalize transforms relative paths of files to absolute.
func (c *Config) Normalize() *Config {
	if c.JSONOutputFilePath != "" {
		c.JSONOutputFilePath, _ = filepath.Abs(c.JSONOutputFilePath)
	}
	c.ProjectPath, _ = filepath.Abs(c.ProjectPath)
	c.ConfigFilePath, _ = filepath.Abs(c.ConfigFilePath)
	c.LogFilePath, _ = filepath.Abs(c.LogFilePath)
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
