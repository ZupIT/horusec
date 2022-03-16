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

	"github.com/ZupIT/horusec-devkit/pkg/enums/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/utils/env"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/google/uuid"
	"github.com/iancoleman/strcase"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/ZupIT/horusec/cmd/app/version"
	"github.com/ZupIT/horusec/config/dist"
	customimages "github.com/ZupIT/horusec/internal/entities/custom_images"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/entities/workdir"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	jsonutils "github.com/ZupIT/horusec/internal/utils/json"
	"github.com/ZupIT/horusec/internal/utils/valueordefault"
)

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
	EnvEnableSemanticEngine            = "HORUSEC_CLI_ENABLE_SEMANTIC_ENGINE"
)

type GlobalOptions struct {
	// TODO: Remove this field.
	// IsTimeout is not a configuration value.
	// IsTimeout just exists to communicate that analysis
	// exceed the timeout configuration.
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
	EnableSemanticEngine            bool                      `json:"enable_semantic_engine"`
	SeveritiesToIgnore              []string                  `json:"severities_to_ignore"`
	FilesOrPathsToIgnore            []string                  `json:"files_or_paths_to_ignore"`
	FalsePositiveHashes             []string                  `json:"false_positive_hashes"`
	RiskAcceptHashes                []string                  `json:"risk_accept_hashes"`
	ShowVulnerabilitiesTypes        []string                  `json:"show_vulnerabilities_types"`
	ToolsConfig                     toolsconfig.ToolsConfig   `json:"tools_config"`
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
		Version: version.Version,
		GlobalOptions: GlobalOptions{
			ConfigFilePath: filepath.Join(wd, "horusec-config.json"),
			LogLevel:       logrus.InfoLevel.String(),
			LogFilePath: filepath.Join(
				os.TempDir(), fmt.Sprintf("horusec-%s.log", time.Now().Format("2006-01-02-15-04-05")),
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
			WorkDir:                         workdir.Default(),
			EnableGitHistoryAnalysis:        false,
			CertInsecureSkipVerify:          false,
			CertPath:                        "",
			EnableCommitAuthor:              false,
			RepositoryName:                  filepath.Base(wd),
			RiskAcceptHashes:                make([]string, 0),
			FalsePositiveHashes:             make([]string, 0),
			Headers:                         make(map[string]string),
			ContainerBindProjectPath:        "",
			ToolsConfig:                     toolsconfig.Default(),
			ShowVulnerabilitiesTypes:        []string{vulnerability.Vulnerability.ToString()},
			CustomImages:                    customimages.Default(),
			DisableDocker:                   dist.IsStandAlone(),
			CustomRulesPath:                 "",
			EnableInformationSeverity:       false,
			EnableOwaspDependencyCheck:      false,
			EnableShellCheck:                false,
			EnableSemanticEngine:            false,
		},
	}
}

// LoadGlobalFlags load global flags into current config instance.
func (c *Config) LoadGlobalFlags(cmd *cobra.Command) *Config {
	c.LogLevel = c.extractFlagValueString(cmd, "log-level", c.LogLevel)
	c.ConfigFilePath = c.extractFlagValueString(cmd, "config-file-path", c.ConfigFilePath)
	c.LogFilePath = c.extractFlagValueString(cmd, "log-file-path", c.LogFilePath)
	return c
}

// LoadGlobalFlags load start command flags into current config instance.
//
//nolint:funlen
func (c *Config) LoadStartFlags(cmd *cobra.Command) *Config {
	c.MonitorRetryInSeconds = c.extractFlagValueInt64(cmd, "monitor-retry-count", c.MonitorRetryInSeconds)
	c.PrintOutputType = c.extractFlagValueString(cmd, "output-format", c.PrintOutputType)
	c.JSONOutputFilePath = c.extractFlagValueString(cmd, "json-output-file", c.JSONOutputFilePath)
	c.SeveritiesToIgnore = c.extractFlagValueStringSlice(cmd, "ignore-severity", c.SeveritiesToIgnore)
	c.FilesOrPathsToIgnore = c.extractFlagValueStringSlice(cmd, "ignore", c.FilesOrPathsToIgnore)
	c.HorusecAPIUri = c.extractFlagValueString(cmd, "horusec-url", c.HorusecAPIUri)
	c.TimeoutInSecondsRequest = c.extractFlagValueInt64(cmd, "request-timeout", c.TimeoutInSecondsRequest)
	c.TimeoutInSecondsAnalysis = c.extractFlagValueInt64(cmd, "analysis-timeout", c.TimeoutInSecondsAnalysis)
	c.RepositoryAuthorization = c.extractFlagValueString(cmd, "authorization", c.RepositoryAuthorization)
	c.Headers = c.extractFlagValueStringToString(cmd, "headers", c.Headers)
	c.ReturnErrorIfFoundVulnerability = c.extractFlagValueBool(cmd, "return-error", c.ReturnErrorIfFoundVulnerability)
	c.ProjectPath = c.extractFlagValueString(cmd, "project-path", c.ProjectPath)
	c.EnableGitHistoryAnalysis = c.extractFlagValueBool(cmd, "enable-git-history", c.EnableGitHistoryAnalysis)
	c.CertInsecureSkipVerify = c.extractFlagValueBool(cmd, "insecure-skip-verify", c.CertInsecureSkipVerify)
	c.CertPath = c.extractFlagValueString(cmd, "certificate-path", c.CertPath)
	c.EnableCommitAuthor = c.extractFlagValueBool(cmd, "enable-commit-author", c.EnableCommitAuthor)
	c.RepositoryName = c.extractFlagValueString(cmd, "repository-name", c.RepositoryName)
	c.FalsePositiveHashes = c.extractFlagValueStringSlice(cmd, "false-positive", c.FalsePositiveHashes)
	c.RiskAcceptHashes = c.extractFlagValueStringSlice(cmd, "risk-accept", c.RiskAcceptHashes)
	c.ContainerBindProjectPath = c.extractFlagValueString(
		cmd, "container-bind-project-path", c.ContainerBindProjectPath,
	)
	c.DisableDocker = c.extractFlagValueBool(cmd, "disable-docker", c.DisableDocker)
	c.CustomRulesPath = c.extractFlagValueString(cmd, "custom-rules-path", c.CustomRulesPath)
	c.EnableInformationSeverity = c.extractFlagValueBool(cmd, "information-severity", c.EnableInformationSeverity)
	c.ShowVulnerabilitiesTypes = c.extractFlagValueStringSlice(
		cmd, "show-vulnerabilities-types", c.ShowVulnerabilitiesTypes,
	)
	c.EnableOwaspDependencyCheck = c.extractFlagValueBool(
		cmd, "enable-owasp-dependency-check", c.EnableOwaspDependencyCheck,
	)
	c.EnableShellCheck = c.extractFlagValueBool(cmd, "enable-shellcheck", c.EnableShellCheck)
	c.EnableSemanticEngine = c.extractFlagValueBool(cmd, "engine.enable-semantic", c.EnableSemanticEngine)
	return c
}

// LoadFromConfigFile load config values from config file into current
// config instance. Note the values loaded from config file will override
// current config instance.
//
//nolint:funlen
func (c *Config) LoadFromConfigFile() *Config {
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

	if wd := viper.GetStringMap(c.toLowerCamel(EnvWorkDir)); wd != nil {
		c.WorkDir = workdir.MustParseWorkDir(wd)
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

	if cfg := viper.GetStringMap(c.toLowerCamel(EnvToolsConfig)); cfg != nil {
		c.ToolsConfig = toolsconfig.MustParseToolsConfig(cfg)
	}

	c.DisableDocker = viper.GetBool(c.toLowerCamel(EnvDisableDocker))
	c.CustomRulesPath = valueordefault.GetStringValueOrDefault(
		viper.GetString(c.toLowerCamel(EnvCustomRulesPath)), c.CustomRulesPath,
	)
	c.EnableInformationSeverity = viper.GetBool(c.toLowerCamel(EnvEnableInformationSeverity))

	if images := viper.GetStringMap(c.toLowerCamel(EnvCustomImages)); images != nil {
		c.CustomImages = customimages.MustParseCustomImages(images)
	}

	c.ShowVulnerabilitiesTypes = valueordefault.GetSliceStringValueOrDefault(
		viper.GetStringSlice(c.toLowerCamel(EnvShowVulnerabilitiesTypes)), c.ShowVulnerabilitiesTypes,
	)
	c.LogFilePath = valueordefault.GetStringValueOrDefault(
		viper.GetString(c.toLowerCamel(EnvLogFilePath)), c.LogFilePath,
	)
	c.EnableOwaspDependencyCheck = viper.GetBool(c.toLowerCamel(EnvEnableOwaspDependencyCheck))
	c.EnableShellCheck = viper.GetBool(c.toLowerCamel(EnvEnableShellCheck))
	c.EnableSemanticEngine = viper.GetBool(c.toLowerCamel(EnvEnableSemanticEngine))
	return c
}

// LoadFromEnvironmentVariables load config values from environment variables into
// current config instance. Note the values loaded from environment variables will
// override current config instance.
//
//nolint:lll,funlen
func (c *Config) LoadFromEnvironmentVariables() *Config {
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
	c.EnableSemanticEngine = env.GetEnvOrDefaultBool(EnvEnableSemanticEngine, c.EnableShellCheck)
	return c
}

// PersistentPreRun is a hook that load user input from command line, config file
// and environment variable.
// We need first read global flags from command line, and them read the config file.
// since the user can manipulate the path. Then we read environment variables if they
// exists (will override the values from config file). Finally we read the flags from
// start command that can override values from config file and environment variables.
//
// After each read values step we normalize the paths from relative to absolute and
// finally configure and create the log file.
func (c *Config) PersistentPreRun(cmd *cobra.Command, _ []string) error {
	err := c.
		LoadGlobalFlags(cmd).
		Normalize().
		LoadFromConfigFile().
		Normalize().
		LoadFromEnvironmentVariables().
		Normalize().
		LoadStartFlags(cmd).
		Normalize().
		ConfigureLogger()
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorSettingLogFile, err)
	}

	return nil
}

// ConfigureLogger create the log file and configure the log output.
func (c *Config) ConfigureLogger() error {
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
		logger.LogWarn(messages.MsgWarnConfigFileNotFoundOnPath)
		return false
	}
	viper.SetConfigFile(c.ConfigFilePath)
	logger.LogPanicWithLevel(messages.MsgPanicGetConfigFilePath, viper.ReadInConfig())
	return true
}

func (c *Config) Bytes() []byte {
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
		c.toLowerCamel(EnvEnableSemanticEngine):            c.EnableSemanticEngine,
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
	cmd *cobra.Command, name string, defaultValue map[string]string,
) map[string]string {
	if cmd.PersistentFlags().Changed(name) {
		flagValue, err := cmd.PersistentFlags().GetStringToString(name)
		logger.LogPanicWithLevel(messages.MsgPanicGetFlagValue, err)
		return flagValue
	}
	return defaultValue
}
