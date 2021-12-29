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

package messages

// Block of messages usage into error response
const (
	MsgErrorPathNotValid                        = "invalid path:"
	MsgErrorJSONOutputFilePathNotValidExtension = "Output File path not valid file of type:"
	MsgErrorJSONOutputFilePathNotValidUnknown   = "Output File path is required or is invalid:"
	MsgErrorSeverityNotValid                    = "Type of severity not valid. See severities enable:"
	MsgErrorAskForUserCancelled                 = "{HORUSEC_CLI} Operation was canceled by user"
	MsgVulnerabilityTypeToShowInvalid           = "{HORUSEC_CLI} Error on validate vulnerability type is wrong type: "
	MsgErrorRunToolInDocker                     = "{HORUSEC_CLI} Something error went wrong in {{0}} tool " +
		"| analysisID -> {{1}} | output -> {{2}}"
	MsgErrorInvalidWorkDir           = "{HORUSEC_CLI} Workdir is nil! Check the configuration and try again"
	MsgErrorParseStringToToolsConfig = "{HORUSEC_CLI} Error when try parse tools config string to entity. " +
		"Returning default values"
	MsgErrorNotFoundRequirementsTxt = "{HORUSEC_CLI} Error The file requirements.txt not found in python project to " +
		"start analysis. It would be a good idea to commit it so horusec can check for vulnerabilities"
	MsgErrorPacketJSONNotFound = "{HORUSEC_CLI} Error It looks like your project doesn't have a package-lock.json " +
		"file. If you use NPM to handle your dependencies, it would be a good idea to commit it so horusec can check " +
		"for vulnerabilities"
	MsgErrorYarnLockNotFound = "{HORUSEC_CLI} Error It looks like your project doesn't have a yarn.lock file. " +
		"If you use Yarn to handle your dependencies, it would be a good idea to commit it so horusec " +
		"can check for vulnerabilities"
	MsgErrorYarnProcess     = "{HORUSEC_CLI} Error Yarn returned an error: "
	MsgErrorGemLockNotFound = "{HORUSEC_CLI} Error It looks like your project doesn't have a gemfile.lock file, " +
		"it would be a good idea to commit it so horusec can check for vulnerabilities"
	MsgErrorGetFilenameByExt = "Could not get filename by extension: "
	MsgErrorNancyRateLimit   = `{HORUSEC_CLI} Nancy tool failed to query the GitHub API for updates.
This is most likely due to GitHub rate-limiting on unauthenticated requests.
To make authenticated requests please:
  1. Generate a token at https://github.com/settings/tokens
  2. Set the token by setting the GITHUB_TOKEN environment variable.
Instructions for generating a token can be found at:
https://help.github.com/articles/creating-a-personal-access-token-for-the-command-line. `
)

// Block of messages usage into log of the level error
const (
	MsgErrorFalsePositiveNotValid        = "False positive is not valid because is duplicated in risk accept:"
	MsgErrorRiskAcceptNotValid           = "Risk Accept is not valid because is duplicated in false positive:"
	MsgErrorWhenCheckRequirementsGit     = "{HORUSEC_CLI} Error when check if git requirement it's ok!"
	MsgErrorWhenCheckRequirementsDocker  = "{HORUSEC_CLI} Error when check if docker requirement it's ok!"
	MsgErrorWhenCheckDockerRunning       = "{HORUSEC_CLI} Error when check if docker is running."
	MsgErrorWhenDockerIsLowerVersion     = "{HORUSEC_CLI} Your docker version is below of: "
	MsgErrorWhenGitIsLowerVersion        = "{HORUSEC_CLI} Your git version is below of: "
	MsgErrorRemoveAnalysisFolder         = "{HORUSEC_CLI} Error when remove analysis project inside .horusec"
	MsgErrorDetectLanguage               = "{HORUSEC_CLI} Error when detect language"
	MsgErrorCopyProjectToHorusecAnalysis = "{HORUSEC_CLI} Error when copy project to .horusec folder"
	MsgErrorGenerateJSONFile             = "{HORUSEC_CLI} Error when try parse horusec analysis to output"
	MsgErrorDockerPullImage              = "{HORUSEC_CLI} Error when pull new image: "
	MsgErrorDockerListImages             = "{HORUSEC_CLI} Error when list all images enable: "
	MsgErrorDockerCreateContainer        = "{HORUSEC_CLI} Error when create container of analysis: "
	MsgErrorDockerStartContainer         = "{HORUSEC_CLI} Error when start container of analysis: "
	MsgErrorDockerListAllContainers      = "{HORUSEC_CLI} Error when list all containers of analysis: "
	MsgErrorDockerRemoveContainer        = "{HORUSEC_CLI} Error when remove container of analysis: "
	MsgErrorGitCommitAuthorsExecute      = "{HORUSEC_CLI} Error when execute commit author command: "
	MsgErrorGitCommitAuthorsParseOutput  = "{HORUSEC_CLI} Error when to parse output to commit author struct: "
	MsgErrorParseStringToWorkDir         = "{HORUSEC_CLI} Error when try parse workdir string to entity." +
		"Returning default values"
	MsgErrorDeferFileClose           = "{HORUSEC_CLI} Error defer file close: "
	MsgErrorSetHeadersOnConfig       = "{HORUSEC-CLI} Error on set headers on configurations"
	MsgErrorReplayWrong              = "{HORUSEC-CLI} Error on set reply, Please type Y or N. Your current response was: "
	MsgErrorErrorOnCreateConfigFile  = "{HORUSEC-CLI} Error on create config file: "
	MsgErrorErrorOnReadConfigFile    = "{HORUSEC-CLI} Error on read config file on path: "
	MsgErrorFailedToPullImage        = "{HORUSEC_CLI} Failed to pull docker image"
	MsgErrorWhileParsingCustomImages = "{HORUSEC_CLI} Error when parsing custom images config. Using default values"
	MsgErrorSettingLogFile           = "{HORUSEC_CLI} Error when setting log file"
	MsgErrorGetRelativePathFromFile  = "{HORUSEC_CLI} Error when get relative path of file"
)
