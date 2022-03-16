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

package testutil

// Available Commands
const (
	CmdVersion  = "version"
	CmdStart    = "start"
	CmdGenerate = "generate"
)

// Available Global Flags
const (
	GlobalFlagConfigFilePath = "--config-file-path"
	GlobalFlagHelp           = "--help"
	GlobalFlagLogFilePath    = "--log-file-path"
	GlobalFlagLogLevel       = "--log-level"
)

// Available Flags for start command
const (
	StartFlagAnalysisTimeout            = "--analysis-timeout"
	StartFlagAuthorization              = "--authorization"
	StartFlagCertificatePath            = "--certificate-path"
	StartFlagContainerBindProjectPath   = "--container-bind-project-path"
	StartFlagCustomRulesPath            = "--custom-rules-path"
	StartFlagDisableDocker              = "--disable-docker"
	StartFlagEnableCommitAuthor         = "--enable-commit-author"
	StartFlagEnableGitHistory           = "--enable-git-history"
	StartFlagEnableOwaspDependencyCheck = "--enable-owasp-dependency-check"
	StartFlagEnableShellcheck           = "--enable-shellcheck"
	StartFlagFalsePositive              = "--false-positive"
	StartFlagHeaders                    = "--headers"
	StartFlagHorusecURL                 = "--horusec-url"
	StartFlagIgnore                     = "--ignore"
	StartFlagIgnoreSeverity             = "--ignore-severity"
	StartFlagInformationSeverity        = "--information-severity"
	StartFlagInsecureSkipVerify         = "--insecure-skip-verify"
	StartFlagJSONOutputFilePath         = "--json-output-file"
	StartFlagMonitorRetryCount          = "--monitor-retry-count"
	StartFlagOutputFormat               = "--output-format"
	StartFlagProjectPath                = "--project-path"
	StartFlagRepositoryName             = "--repository-name"
	StartFlagRequestTimeout             = "--request-timeout"
	StartFlagReturnError                = "--return-error"
	StartFlagRiskAccept                 = "--risk-accept"
	StartFlagShowVulnerabilitiesTypes   = "--show-vulnerabilities-types"
	StartEngineEnableSemantic           = "--engine.enable-semantic"
)

func GetAllStartFlags() []string {
	return []string{
		StartFlagAnalysisTimeout, StartFlagAuthorization, StartFlagCertificatePath,
		StartFlagContainerBindProjectPath, StartFlagCustomRulesPath, StartFlagDisableDocker,
		StartFlagEnableCommitAuthor, StartFlagEnableGitHistory, StartFlagEnableOwaspDependencyCheck,
		StartFlagEnableShellcheck, StartFlagFalsePositive, StartFlagHeaders,
		StartFlagHorusecURL, StartFlagIgnore, StartFlagIgnoreSeverity,
		StartFlagInformationSeverity, StartFlagInsecureSkipVerify, StartFlagJSONOutputFilePath,
		StartFlagMonitorRetryCount, StartFlagOutputFormat, StartFlagProjectPath,
		StartFlagRepositoryName, StartFlagRequestTimeout, StartFlagReturnError,
		StartFlagRiskAccept, StartFlagShowVulnerabilitiesTypes, StartEngineEnableSemantic,
	}
}
