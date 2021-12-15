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

// Block of messages usage into log of the level debug
const (
	MsgDebugDockerAPIPullNewImage        = "{HORUSEC_CLI} Docker pull new image: "
	MsgDebugDockerAPIDownloadWithSuccess = "{HORUSEC_CLI} Docker download new image with success: "
	MsgDebugDockerAPIContainerCreated    = "{HORUSEC_CLI} Docker create new container: "
	MsgDebugDockerAPIContainerWait       = "{HORUSEC_CLI} Docker wait container up..."
	MsgDebugDockerAPIContainerRead       = "{HORUSEC_CLI} Docker read container output: "
	MsgDebugDockerAPIFinishedSuccess     = "{HORUSEC_CLI} Docker Finished analysis with SUCCESS: "
	MsgDebugDockerAPIFinishedError       = "{HORUSEC_CLI} Docker Finished analysis with ERROR: "
	MsgDebugToolStartAnalysis            = "{HORUSEC_CLI} Running {{0}} - {{1}} in analysisID: "
	MsgDebugToolFinishAnalysis           = "{HORUSEC_CLI} {{0}} - {{1}} is finished in analysisID: "
	MsgDebugOutputEmpty                  = "{HORUSEC_CLI} When format Output it's Empty!"
	MsgDebugConfigFileRunningOnPath      = "{HORUSEC_CLI} Config file running on path: "
	MsgDebugFolderOrFileIgnored          = "{HORUSEC_CLI} The file or folder was ignored to send analysis:"
	MsgDebugShowConfigs                  = "{HORUSEC_CLI} The current configuration for this analysis are:"
	MsgDebugShowWorkdir                  = "{HORUSEC_CLI} Using path %s as workdir to run tool %s"
	MsgDebugToolIgnored                  = "{HORUSEC_CLI} The tool was ignored for run in this analysis: "
	MsgDebugVulnHashToFix                = "{HORUSEC_CLI} Vulnerability Hash expected to be FIXED: "
	MsgDebugDockerImageDoesNotExists     = "{HORUSEC_CLI} Image %s does not exists. Pulling from registry"
)
