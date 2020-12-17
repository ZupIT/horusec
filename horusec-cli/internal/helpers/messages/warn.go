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
	// Fired when not found authorization token
	MsgWarnAuthorizationNotFound = "{HORUSEC_CLI} No authorization token was found, " +
		"your code it is not going to be sent to horusec. " +
		"Please enter a token with the -a flag to configure and save your analysis"
	// Fired when return success in copy project to .horusec folder
	MsgWarnDontRemoveHorusecFolder = "{HORUSEC_CLI} PLEASE DON'T REMOVE \".horusec\" FOLDER BEFORE THE ANALYSIS FINISH!" +
		" Don’t worry, we’ll remove it after the analysis ends automatically! Project sent to folder in location: "
	// Fired when bandit found vulnerability but is not really an vulnerability and yes an informative assert detected
	MsgWarnBanditFoundInformative = "{HORUSEC_CLI} CAUTION! In your project was found {{0}} details of type: "
	// Fired when occurs of ignore folder or file to send horusec analysis
	MsgWarnTotalFolderOrFileWasIgnored = "{HORUSEC_CLI} When starting the analysis WE SKIP A TOTAL OF {{0}} FILES " +
		"that are not considered to be analyzed. To see more details use flag --log-level=debug"
	MsgWarnGitHistoryEnable = "{HORUSEC_CLI} Starting the analysis with git history enabled. " +
		"ATTENTION the waiting time can be longer when this option is enabled!"
	MsgWarnNetCoreDeprecated = "{HORUSEC_CLI} The 'netcore' key will be removed in the next release after 23 dec 2020," +
		" please use csharp key in workdir"
	MsgWarnToolsToIgnoreDeprecated = "{HORUSEC_CLI} The option 'tools to ignore' key will be removed in the next release" +
		" after 16 jan 2021, please use tools config option"
	MsgWarnHashNotExistOnAnalysis = "{HORUSEC_CLI} Hash not found in the list of vulnerabilities pointed out by Horusec: "
)
