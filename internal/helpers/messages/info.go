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

// Block of messages usage into log of the level info
const (
	MsgInfoConfigAlreadyExist       = `{HORUSEC_CLI} Horusec configuration already exists on path: `
	MsgInfoConfigFileCreatedSuccess = `{HORUSEC_CLI} Horusec created file of configuration with success on path: `
	MsgInfoHowToInstallDocker       = `{HORUSEC_CLI} If your docker is not installed check in docs of how to install in:
		https://docs.docker.com/get-docker
	`
	MsgInfoHowToInstallGit = `{HORUSEC_CLI} If your git is not installed check in docs of how to install in:
		https://git-scm.com/downloads
	`
	MsgInfoStartGenerateSonarQubeFile = "{HORUSEC_CLI} Generating SonarQube output..."
	MsgInfoStartGenerateSARIFFile     = "{HORUSEC_CLI} Generating SARIF output..."
	MsgInfoStartWriteFile             = "{HORUSEC_CLI} Writing output JSON to file in the path: "
	MsgInfoAnalysisLoading            = " Scanning code ..."
	MsgInfoDockerLowerVersion         = "{HORUSEC_CLI} We recommend version 19.03 or higher of the docker." +
		" Versions prior to this may have problems during execution"
)
