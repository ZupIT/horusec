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
	entitiesAnalysis "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	engine "github.com/ZupIT/horusec-engine"
	commitAuthor "github.com/ZupIT/horusec/internal/entities/commit_author"
	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
)

type IFormatter interface {
	StartAnalysis(projectSubPath string)
}

type IService interface {
	LogDebugWithReplace(msg string, tool tools.Tool, lang languages.Language)
	GetAnalysisID() string
	ExecuteContainer(data *dockerEntities.AnalysisData) (output string, err error)
	GetAnalysisIDErrorMessage(tool tools.Tool, output string) string
	GetCommitAuthor(line, filePath string) (commitAuthor commitAuthor.CommitAuthor)
	AddWorkDirInCmd(cmd string, projectSubPath string, tool tools.Tool) string
	GetConfigProjectPath() string
	GetToolsConfig() toolsconfig.MapToolConfig
	GetAnalysis() *entitiesAnalysis.Analysis
	SetAnalysisError(err error, tool tools.Tool, projectSubPath string)
	RemoveSrcFolderFromPath(filepath string) string
	GetCodeWithMaxCharacters(code string, column int) string
	ToolIsToIgnore(tool tools.Tool) bool
	GetFilepathFromFilename(filename, projectSubPath string) string
	GetProjectPathWithWorkdir(projectSubPath string) string
	SetCommitAuthor(vulnerability *vulnerability.Vulnerability) *vulnerability.Vulnerability
	ParseFindingsToVulnerabilities(findings []engine.Finding, tool tools.Tool, language languages.Language) error
	AddNewVulnerabilityIntoAnalysis(vulnerability *vulnerability.Vulnerability)
	IsDockerDisabled() bool
	GetCustomRulesByLanguage(lang languages.Language) []engine.Rule
	GetConfigCMDByFileExtension(projectSubPath, imageCmd, ext string, tool tools.Tool) string
	GetCustomImageByLanguage(language languages.Language) string
	IsOwaspDependencyCheckDisable() bool
}
