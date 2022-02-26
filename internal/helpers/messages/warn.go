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

// Block of messages usage into log of the level warn
const (
	MsgWarnAuthorizationNotFound = "{HORUSEC_CLI} No authorization token was found, " +
		"your code it is not going to be sent to horusec. " +
		"Please enter a token with the -a flag to configure and save your analysis"
	MsgWarnDontRemoveHorusecFolder = "{HORUSEC_CLI} PLEASE DON'T REMOVE \".horusec\" FOLDER BEFORE THE ANALYSIS FINISH!" +
		" Don’t worry, we’ll remove it after the analysis ends automatically! Project sent to folder in location: "
	MsgWarnBanditFoundInformative = "{HORUSEC_CLI} CAUTION! In your project was found " +
		"{{0}} details of type informative"
	MsgWarnTotalFolderOrFileWasIgnored = "{HORUSEC_CLI} When starting the analysis WE SKIP A TOTAL OF %d FILES " +
		"that are not considered to be analyzed. To see more details use flag --log-level=debug"
	MsgWarnGitHistoryEnable = "{HORUSEC_CLI} Starting the analysis with git history enabled. " +
		"ATTENTION the waiting time can be longer when this option is enabled!"
	MsgWarnHashNotExistOnAnalysis = "{HORUSEC_CLI} Hash not found in the " +
		"list of vulnerabilities pointed out by Horusec: "
	MsgWarnInfoVulnerabilitiesDisabled = "{HORUSEC_CLI} Horusec not show info vulnerabilities in this analysis, " +
		"to see info vulnerabilities add option \"--information-severity=true\". " +
		"For more details use (horusec start --help) command."
	MsgWarnMonitorTimeoutIn = "Horusec will return a timeout after %d seconds. " +
		"This time can be customized in the cli settings."
	MsgWarnAnalysisFoundVulns = "{HORUSEC_CLI} %d VULNERABILITIES WERE FOUND IN YOUR CODE SENT TO HORUSEC, " +
		"TO SEE MORE DETAILS USE THE LOG LEVEL AS DEBUG AND TRY AGAIN"
	MsgWarnAnalysisFinishedWithoutVulns = "YOUR ANALYSIS HAD FINISHED WITHOUT ANY VULNERABILITY!"
	MsgWarnConfigFileNotFoundOnPath     = "{HORUSEC_CLI} Config file not found"

	MsgWarnTimeoutOccurs = "{HORUSEC_CLI} Some analysis was not completed due to the timeout, " +
		"increase the time with -t flag and try again."
	MsgWarnWhenAskDirToRun = "{HORUSEC_CLI} Error when ask if can run prompt question.: \n" +
		"Please use the command below informing the directory you want to run the analysis: \n" +
		"horusec start -p ./"
	MsgWarnFoundErrorsInAnalysis        = "{HORUSEC_CLI} During execution we found some problems:"
	MsgWarnGitRepositoryIsNotFullCloned = "{HORUSEC_CLI} Repository is not fully cloned." +
		"Commit author can result wrong authors. Check the documentation for more info." +
		"https://docs.horusec.io/docs/cli/installation/#2-installation-via-pipeline"

	// TODO: Remove MsgWarnUpdateOutdatedHash before release v2.10.0
	MsgWarnUpdateOutdatedHash = "{HORUSEC_CLI} Update hash %s to %s"

	// TODO: Remove MsgWarnAnalysisContainsOutdatedHash before release v2.10.0
	MsgWarnAnalysisContainsOutdatedHash = "{HORUSEC_CLI} YOUR CONFIGURATION FILE CONTAINS SOME HASHES THAT WILL NO " +
		"LONGER BE VALID AS OF v2.10.0 IS RELEASED. PLEASE UPDATE YOUR CONFIGURATION FILE WITH THE FOLLOWING HASHES:"
	MsgWarnPathIsInvalidGitRepository = "{HORUSEC_CLI} The current path it's not a valid git repository"
)
