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
	// Fired when is necessary show how to install docker
	MsgInfoHowToInstallDocker = `{HORUSEC_CLI} If your docker is not installed check in docs of how to install in:
		https://docs.docker.com/get-docker
	`
	// Fired when is necessary show how to install git
	MsgInfoHowToInstallGit = `{HORUSEC_CLI} If your git is not installed check in docs of how to install in:
		https://git-scm.com/downloads
	`
	// Fired when the user passed a configuration file and we must show where it is located
	MsgInfoConfigFilePath = "{HORUSEC_CLI} Using config file: "
	// Fired when is setup to the output is sonarqube
	MsgInfoStartGenerateSonarQubeFile = "{HORUSEC_CLI} Generating SonarQube output..."
	// Fired when is setup to the output is sonarqube
	MsgInfoStartWriteFile = "{HORUSEC_CLI} Writing output JSON to file in the path: "
	// Fired when monitor log timeout
	MsgInfoMonitorTimeoutIn = "Hold on! Horusec still analysis your code. Timeout in: "
	// Fired in print results service when analysis is finished
	MsgAnalysisFoundVulns = "[HORUSEC] %d VULNERABILITIES WERE FOUND IN YOUR CODE SENT TO HORUSEC, SEE MORE DETAILS IN DEBUG LEVEL AND TRY AGAIN"
	// Fired in print results service when analysis is finished
	MsgAnalysisFinishedWithoutVulns = "YOUR ANALYSIS HAD FINISHED WITHOUT ANY VULNERABILITY!"
)
