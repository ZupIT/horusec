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
	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	engine "github.com/ZupIT/horusec-engine"

	"github.com/ZupIT/horusec/internal/entities/docker"
)

// IFormatter is the interface that tools implement to run an
// analysis and convert its results to Horusec results.
type IFormatter interface {
	StartAnalysis(projectSubPath string)
}

// IService is the service used by tools to start analysis on docker,
// transform file paths and manipulate analysis information such as
// vulnerabilities.
type IService interface {
	LogDebugWithReplace(msg string, tool tools.Tool, lang languages.Language)

	// GetAnalysisID return the ID of current analysis.
	GetAnalysisID() string

	// ExecuteContainer execute a container using info from data input
	// and return the data.CMD output or error if exists.
	ExecuteContainer(data *docker.AnalysisData) (output string, err error)

	// GetAnalysisIDErrorMessage returns a string message containing
	// error information with the current analysis id, the tool that
	// generate the error and the error itself.
	GetAnalysisIDErrorMessage(tool tools.Tool, output string) string

	// AddWorkDirInCmd replace {{WORK_DIR}} from cmd with a `cd` into projectSubPath.
	AddWorkDirInCmd(cmd string, projectSubPath string, tool tools.Tool) string

	// GetConfigProjectPath return the project path of analysis. Note that the project
	// path returned is the .horusec/ANALYSIS-ID directory created to execute analysis
	// (It's not the project path informed by user).
	GetConfigProjectPath() string

	// SetAnalysisError add an error from a tool to current analysis.
	SetAnalysisError(err error, tool tools.Tool, output, projectSubPath string)

	// RemoveSrcFolderFromPath remove src prefix from filepath.
	RemoveSrcFolderFromPath(filepath string) string

	// GetCodeWithMaxCharacters returns the code limited to the MaxCharacters.
	GetCodeWithMaxCharacters(code string, column int) string

	// ToolIsToIgnore check if a tool should be ignored.
	ToolIsToIgnore(tool tools.Tool) bool

	// GetFilepathFromFilename return the relative file path inside projectSubpath
	// to a given filename
	GetFilepathFromFilename(filename, projectSubPath string) (string, error)

	// SetCommitAuthor set commit author info on vulnerability.
	SetCommitAuthor(vulnerability *vulnerability.Vulnerability) *vulnerability.Vulnerability

	// ParseFindingsToVulnerabilities convert findings to vulnerabilities and add these
	// vulnerabilities on current analysis.
	ParseFindingsToVulnerabilities(findings []engine.Finding, tool tools.Tool, language languages.Language)

	// AddNewVulnerabilityIntoAnalysis add vulnerability on current analysis.
	AddNewVulnerabilityIntoAnalysis(vulnerability *vulnerability.Vulnerability)

	// GetCustomRulesByLanguage return user custom rules to a given language.
	GetCustomRulesByLanguage(lang languages.Language) []engine.Rule

	// GetCustomImageByLanguage return a custom docker image to a given language.
	GetCustomImageByLanguage(language languages.Language) string

	// GetConfigCMDByFileExtension works like AddWorkDirInCmd but use a sub path
	// that contains files that match ext extension. If this sub path was not found
	// the project sub path returned from GetConfigProjectPath is used.
	GetConfigCMDByFileExtension(projectSubPath, imageCmd, ext string, tool tools.Tool) string

	// IsDockerDisabled return true if docker is disable, otherwise false.
	IsDockerDisabled() bool

	// IsOwaspDependencyCheckDisable return true if dependency check is disable
	// otherwise false.
	IsOwaspDependencyCheckDisable() bool

	// IsShellcheckDisable return true if shell check is disable, otherwise false.
	IsShellcheckDisable() bool

	// IsSemanticEngineEnable return true if experimental semantic engine is enabled, otherwise false.
	IsSemanticEngineEnable() bool
}
