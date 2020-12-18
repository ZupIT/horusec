package config

import (
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/horusec-cli/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/horusec-cli/internal/entities/workdir"
	"github.com/spf13/cobra"
)

type IConfig interface {
	NewConfigsFromCobraAndLoadsCmdStartFlags(cmd *cobra.Command) IConfig
	NewConfigsFromViper() IConfig
	NewConfigsFromEnvironments() IConfig

	GetConfigFilePath() string
	SetConfigFilePath(configFilePath string)

	GetHorusecAPIUri() string
	SetHorusecAPIURI(horusecAPIURI string)

	GetTimeoutInSecondsRequest() int64
	SetTimeoutInSecondsRequest(timeoutInSecondsRequest int64)

	GetTimeoutInSecondsAnalysis() int64
	SetTimeoutInSecondsAnalysis(timeoutInSecondsAnalysis int64)

	GetMonitorRetryInSeconds() int64
	SetMonitorRetryInSeconds(retryInterval int64)

	GetRepositoryAuthorization() string
	SetRepositoryAuthorization(repositoryAuthorization string)

	GetPrintOutputType() string
	SetPrintOutputType(printOutputType string)

	GetJSONOutputFilePath() string
	SetJSONOutputFilePath(jsonOutputFilePath string)

	GetSeveritiesToIgnore() []string
	SetSeveritiesToIgnore(severitiesToIgnore []string)

	GetFilesOrPathsToIgnore() []string
	SetFilesOrPathsToIgnore(filesOrPaths []string)

	GetReturnErrorIfFoundVulnerability() bool
	SetReturnErrorIfFoundVulnerability(returnError bool)

	GetProjectPath() string
	SetProjectPath(projectPath string)

	GetFilterPath() string
	SetFilterPath(filterPath string)

	GetWorkDir() *workdir.WorkDir
	SetWorkDir(toParse interface{})

	GetEnableGitHistoryAnalysis() bool
	SetEnableGitHistoryAnalysis(enableGitHistoryAnalysis bool)

	GetCertInsecureSkipVerify() bool
	SetCertInsecureSkipVerify(certInsecureSkipVerify bool)

	GetCertPath() string
	SetCertPath(certPath string)

	GetEnableCommitAuthor() bool
	SetEnableCommitAuthor(isEnable bool)

	GetRepositoryName() string
	SetRepositoryName(repositoryName string)

	GetRiskAcceptHashes() (output []string)
	SetRiskAcceptHashes(riskAccept []string)

	GetFalsePositiveHashes() (output []string)
	SetFalsePositiveHashes(falsePositive []string)

	GetToolsToIgnore() (output []string)
	SetToolsToIgnore(toolsToIgnore []string)

	GetHeaders() (headers map[string]string)
	SetHeaders(headers interface{})

	GetContainerBindProjectPath() string
	SetContainerBindProjectPath(containerBindProjectPath string)

	GetIsTimeout() bool
	SetIsTimeout(isTimeout bool)

	GetToolsConfig() map[tools.Tool]toolsconfig.ToolConfig
	SetToolsConfig(toolsConfig interface{})

	GetDisableDocker() bool
	SetDisableDocker(disableDocker bool)

	GetCustomRulesPath() string
	SetCustomRulesPath(customRulesPath string)

	IsEmptyRepositoryAuthorization() bool
	ToBytes(isMarshalIndent bool) (bytes []byte)
	NormalizeConfigs() IConfig
}
