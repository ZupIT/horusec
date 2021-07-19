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
	customImages "github.com/ZupIT/horusec/internal/entities/custom_images"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/entities/workdir"
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
	EnvEnableOwaspDependencyCheck      = "HORUSEC_CLI_ENABLE_OWASP_DEPENDENCY_CHECK"
	EnvLogFilePath                     = "HORUSEC_CLI_LOG_FILE_PATH"
)

type Config struct {
	// Global configs
	isTimeout bool

	// Globals Command Flags
	logLevel       string
	configFilePath string
	logFilePath    string

	// Start Command Flags
	horusecAPIUri                   string
	repositoryAuthorization         string
	certPath                        string
	repositoryName                  string
	printOutputType                 string
	jsonOutputFilePath              string
	projectPath                     string
	customRulesPath                 string
	containerBindProjectPath        string
	timeoutInSecondsRequest         int64
	timeoutInSecondsAnalysis        int64
	monitorRetryInSeconds           int64
	returnErrorIfFoundVulnerability bool
	enableGitHistoryAnalysis        bool
	certInsecureSkipVerify          bool
	enableCommitAuthor              bool
	disableDocker                   bool
	enableInformationSeverity       bool
	enableOwaspDependencyCheck      bool
	severitiesToIgnore              []string
	filesOrPathsToIgnore            []string
	falsePositiveHashes             []string
	riskAcceptHashes                []string
	showVulnerabilitiesTypes        []string
	toolsConfig                     toolsconfig.MapToolConfig
	headers                         map[string]string
	workDir                         *workdir.WorkDir
	customImages                    customImages.CustomImages
}
