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
	// Fired when start pull new image in docker
	MsgDebugDockerAPIPullNewImage = "{HORUSEC_CLI} Docker pull new image: "
	// Fired when image was finish download with success
	MsgDebugDockerAPIDownloadWithSuccess = "{HORUSEC_CLI} Docker download new image with success: "
	// Fired when container will be created
	MsgDebugDockerAPIContainerCreated = "{HORUSEC_CLI} Docker create new container: "
	// Fired when wait container start analysis of the project
	MsgDebugDockerAPIContainerWait = "{HORUSEC_CLI} Docker wait container up..."
	// Fired when read container output of the analysis
	MsgDebugDockerAPIContainerRead = "{HORUSEC_CLI} Docker read container output: "
	// Fired when analysis is finished and return success
	MsgDebugDockerAPIFinishedSuccess = "{HORUSEC_CLI} Docker Finished analysis with SUCCESS: "
	// Fired when analysis is finished and return error
	MsgDebugDockerAPIFinishedError = "{HORUSEC_CLI} Docker Finished analysis with ERROR: "
	// Fired when tool start an analysis
	MsgDebugToolStartAnalysis = "{HORUSEC_CLI} Running {{0}} in analysisID: "
	// Fired when tool finish an analysis
	MsgDebugToolFinishAnalysis = "{HORUSEC_CLI} {{0}} is finished in analysisID: "
	// Fired when output of the analysis was run in docker is empty
	MsgDebugOutputEmpty              = "{HORUSEC_CLI} When format Output it's Empty!"
	MsgDebugConfigFileRunningOnPath  = "{HORUSEC_CLI} Config file running on path: "
	MsgDebugConfigFileNotFoundOnPath = "{HORUSEC_CLI} Config file not found"
	// Fired when occurs of ignore folder or file to send horusec analysis
	MsgDebugFolderOrFileIgnored = "{HORUSEC_CLI} The file ou folder was ignored to send analysis:"
	// Fired when configs already validate and before start analysis
	MsgDebugShowConfigs = "{HORUSEC_CLI} The current configuration for this analysis are:"
	MsgDebugShowWorkdir = "{HORUSEC_CLI} The workdir setup for run in path:"
	MsgDebugToolIgnored = "{HORUSEC_CLI} The tool was ignored for run in this analysis: "
)
