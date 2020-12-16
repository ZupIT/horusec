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

const (
	// Fired when occurs timeout on wait analysis Finish
	MsgErrorTimeoutOccurs = "{HORUSEC_CLI} Some analysis was not completed due to the timeout, " +
		"increase the time with -t flag and try again."
	// USED IN USE CASES: Fired when the project path is invalid
	MsgErrorProjectPathNotValid = "project path is invalid: "
	// USED IN USE CASES: Fired when an path of json is not valid in configs
	MsgErrorJSONOutputFilePathNotValid = "JSON File path is required or is invalid: "
	// USED IN USE CASES: Fired when an severity is not allowed in configs
	MsgErrorSeverityNotValid = "Type of severity not valid: "
	// USED IN USE CASES: Fired when an false positive is not allowed in configs
	MsgErrorFalsePositiveNotValid = "False positive is not valid because is duplicated in risk accept: "
	// USED IN USE CASES: Fired when an risk accept is not allowed in configs
	MsgErrorRiskAcceptNotValid = "Risk Accept is not valid because is duplicated in false positive: "
	// Fired when an unexpected error occurs when check if the requirements it's ok
	MsgErrorWhenCheckRequirements = "{HORUSEC_CLI} Error when check if requirements it's ok!"
	// Fired when an unexpected error occurs when check if the docker is running
	MsgErrorWhenCheckDockerRunnnig = "{HORUSEC_CLI} Error when check if docker is running in requirements, "
	// Fired when docker is running in lower version
	MsgErrorWhenDockerIsLowerVersion = "{HORUSEC_CLI} Your docker version is below of: "
	// Fired when git is running in lower version
	MsgErrorWhenGitIsLowerVersion = "{HORUSEC_CLI} Your git version is below of: "
	// Fired when an unexpected error occurs when asking if the project directory is correct
	MsgErrorWhenAskDirToRun = "{HORUSEC_CLI} Error when ask if can run prompt question"
	// Fired when user-provided settings are invalid
	MsgErrorInvalidConfigs = "{HORUSEC_CLI} Errors on validate configuration: "
	// Fired when an unexpected error occurs when try remove analysis folder
	MsgErrorRemoveAnalysisFolder = "{HORUSEC_CLI} Error when remove analysis project inside .horusec"
	// Fired when an unexpected error occurs when try detect languages of the project
	MsgErrorDetectLanguage = "{HORUSEC_CLI} Error when detect language"
	// Fired when an unexpected error occurs when try copy project analysis to .horusec folder
	MsgErrorCopyProjectToHorusecAnalysis = "{HORUSEC_CLI} Error when copy project to .horusec folder"
	// Fired when an unexpected error occurs when try generate files json
	MsgErrorGenerateJSONFile = "{HORUSEC_CLI} Error when try parse horusec analysis to output"
	// Fired when an unexpected error occurs when try pull image in the docker
	MsgErrorDockerPullImage = "{HORUSEC_CLI} Error when pull new image: "
	// Fired when an unexpected error occurs when try pull list images in the docker
	MsgErrorDockerListImages = "{HORUSEC_CLI} Error when list all images enable: "
	// Fired when an unexpected error occurs when try create container of analysis in the docker
	MsgErrorDockerCreateContainer = "{HORUSEC_CLI} Error when create container of analysis: "
	// Fired when an unexpected error occurs when try start container of analysis in the docker
	MsgErrorDockerStartContainer = "{HORUSEC_CLI} Error when start container of analysis: "
	// Fired when an unexpected error occurs when try list all containers of analysis in the docker
	MsgErrorDockerListAllContainers = "{HORUSEC_CLI} Error when list all containers of analysis: "
	// Fired when an unexpected error occurs when try remove container of analysis in the docker
	MsgErrorDockerRemoveContainer = "{HORUSEC_CLI} Error when remove container of analysis: "
	// Fired when an unexpected error occurs when try execute command to extract commit authors of an vulnerability
	MsgErrorGitCommitAuthorsExecute = "{HORUSEC_CLI} Error when execute commit author command: "
	// Fired when an unexpected error occurs when try parse output commit authors to struct CommitAuthors
	MsgErrorGitCommitAuthorsParseOutput = "{HORUSEC_CLI} Error when to parse output to commit author struct: "
	// Fired when an unexpected error occurs when read spotbugs output
	// and return missing classes or found errors in analysis
	MsgSpotBugsMissingClassesOrErrors = "{HORUSEC_CLI} Error spotbugs has risen because of [{{0}}] " +
		"missing classes and [{{1}}] errors while analyzing"
	// Fired when an unexpected error occurs when run tool in docker
	MsgErrorRunToolInDocker = "{HORUSEC_CLI} Something error went wrong in {{0}} tool " +
		"| analysisID -> {{1}} | output -> {{2}}"
	// Fired when to be parse string of the WorkDir Entity and return error
	MsgErrorParseStringToWorkDir = "{HORUSEC_CLI} Error when try parse workdir string to entity. Returning default values"
	// Fired when to be parse string of the WorkDir Entity and return error
	MsgErrorParseStringToToolsConfig = "{HORUSEC_CLI} Error when try parse tools config string to entity." +
		" Returning default values"
	// Fired when finish analysis and send to print results and exists errors in analysis
	MsgErrorFoundErrorsInAnalysis   = "{HORUSEC_CLI} During execution we found some problems:"
	MsgErrorNotFoundRequirementsTxt = "{HORUSEC_CLI} Error The file requirements.txt " +
		"not found in python project to start analysis"
	MsgErrorPacketJSONNotFound = "{HORUSEC_CLI} Error It looks like your project " +
		"doesn't have a package-lock.json file. " +
		"If you use NPM to  handle your dependencies, " +
		"it would be a good idea to commit it so horusec can check for vulnerabilities"
	MsgErrorYarnLockNotFound = "{HORUSEC_CLI} Error It looks like your project doesn't have a yarn.lock file. " +
		"If you use Yarn to handle your dependencies, " +
		"it would be a good idea to commit it so horusec can check for vulnerabilities"
	MsgErrorYarnProcess    = "{HORUSEC_CLI} Error Yarn returned an error: "
	MsgErrorDeferFileClose = "{HORUSEC_CLI} Error defer file close: "
)
