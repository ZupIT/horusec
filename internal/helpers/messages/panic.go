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

// Block of messages usage into log of the level panic
const (
	MsgPanicDockerRequirementsToRunHorusec = "{HORUSEC_CLI} Missing required DOCKER in min. version 19.03 to start"
	MsgPanicGitRequirementsToRunHorusec    = "{HORUSEC_CLI} Missing required GIT in min. version 2.01 to start"
	MsgPanicGetFlagValue                   = "{HORUSEC_CLI} Error on getting flag value, check and try again: "
	MsgPanicNotConnectDocker               = "{HORUSEC_CLI} Error when try connect in docker."
	MsgPanicGetConfigFilePath              = "{HORUSEC-CLI} Error on get config file path."
	PanicMarkHiddenFlag                    = "{HORUSEC-CLI} Internal error occurred to hidden %s flag: "
	PanicMarkDeprecatedFlag                = "{HORUSEC-CLI} Internal error occurred to mark %s flag as deprecated: "
)
