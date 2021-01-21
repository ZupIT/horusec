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

package formatters

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/entities/toolsconfig"
)

type IFormatter interface {
	StartAnalysis(projectSubPath string)
}

type IService interface {
	LogDebugWithReplace(msg string, tool tools.Tool)
	GetAnalysisID() string
	ExecuteContainer(data *dockerEntities.AnalysisData) (output string, err error)
	GetAnalysisIDErrorMessage(tool tools.Tool, output string) string
	GetCommitAuthor(line, filePath string) (commitAuthor horusec.CommitAuthor)
	AddWorkDirInCmd(cmd string, projectSubPath string, tool tools.Tool) string
	GetConfigProjectPath() string
	GetToolsConfig() map[tools.Tool]toolsconfig.ToolConfig
	GetAnalysis() *horusec.Analysis
	SetToolFinishedAnalysis()
	SetAnalysisError(err error, tool tools.Tool, projectSubPath string)
	SetMonitor(monitor *horusec.Monitor)
	RemoveSrcFolderFromPath(filepath string) string
	GetCodeWithMaxCharacters(code string, column int) string
	ToolIsToIgnore(tool tools.Tool) bool
	GetFilepathFromFilename(filename string) string
	GetProjectPathWithWorkdir(projectSubPath string) string
	SetCommitAuthor(vulnerability *horusec.Vulnerability) *horusec.Vulnerability
	ParseFindingsToVulnerabilities(findings []engine.Finding, tool tools.Tool, language languages.Language) error
	AddNewVulnerabilityIntoAnalysis(vulnerability *horusec.Vulnerability)
	IsDockerDisabled() bool
	GetCustomRulesByTool(tool tools.Tool) []engine.Rule
	GetConfigCMDYarnOrNpmAudit(projectSubPath, imageCmd string, tool tools.Tool) string
}
