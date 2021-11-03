// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package dotnetcli

import (
	"fmt"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/services/formatters/csharp/dotnet_cli/entities"
	"github.com/ZupIT/horusec/internal/services/formatters/csharp/dotnet_cli/enums"
	"github.com/ZupIT/horusec/internal/utils/file"
	vulnHash "github.com/ZupIT/horusec/internal/utils/vuln_hash"
)

type Formatter struct {
	formatters.IService
}

func NewFormatter(service formatters.IService) formatters.IFormatter {
	return &Formatter{
		IService: service,
	}
}

func (f *Formatter) StartAnalysis(projectSubPath string) {
	if f.ToolIsToIgnore(tools.DotnetCli) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.DotnetCli.ToString())
		return
	}

	f.SetAnalysisError(f.startDotnetCli(projectSubPath), tools.DotnetCli, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.DotnetCli, languages.CSharp)
}

func (f *Formatter) startDotnetCli(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.DotnetCli, languages.CSharp)

	output, err := f.checkOutputErrors(f.ExecuteContainer(f.getConfigData(projectSubPath)))
	if err != nil {
		return err
	}

	f.parseOutput(output, projectSubPath)
	return nil
}

func (f *Formatter) getConfigData(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD: f.AddWorkDirInCmd(CMD, file.GetSubPathByExtension(
			f.GetConfigProjectPath(), projectSubPath, "*.sln"), tools.DotnetCli),
		Language: languages.CSharp,
	}

	return analysisData.SetData(f.GetCustomImageByLanguage(languages.CSharp), images.Csharp)
}

func (f *Formatter) parseOutput(output, projectSubPath string) {
	if f.isInvalidOutput(output) {
		return
	}
	//nolint
	for _, value := range strings.Split(output[strings.Index(output, enums.Separator):], enums.Separator) {
		dependency := f.parseDependencyValue(value)
		if dependency != nil && *dependency != (entities.Dependency{}) {
			f.AddNewVulnerabilityIntoAnalysis(f.setVulnerabilityData(dependency, projectSubPath))
		}
	}
}

func (f *Formatter) parseDependencyValue(value string) *entities.Dependency {
	dependency := &entities.Dependency{}

	for index, fieldValue := range f.formatOutput(value) {
		if strings.TrimSpace(fieldValue) == "" || strings.TrimSpace(fieldValue) == "\n" {
			continue
		}

		f.parseFieldByIndex(index, fieldValue, dependency)
	}

	return dependency
}

func (f *Formatter) formatOutput(value string) (result []string) {
	value = strings.ReplaceAll(value, "\n", "")
	value = strings.ReplaceAll(value, "\r", "")

	for _, field := range strings.Split(value, "\u001B[39;49m") {
		field = strings.TrimSpace(field)
		if field != "" && strings.TrimSpace(field) != enums.AutoReferencedPacket {
			result = append(result, field)
		}
	}

	return result
}

func (f *Formatter) parseFieldByIndex(index int, fieldValue string, dependency *entities.Dependency) {
	switch index {
	case enums.IndexDependencyName:
		dependency.SetName(fieldValue)
	case enums.IndexDependencyVersion:
		dependency.SetVersion(fieldValue)
	case enums.IndexDependencySeverity:
		dependency.SetSeverity(fieldValue)
	case enums.IndexDependencyDescription:
		dependency.SetDescription(fieldValue)
	}
}

func (f *Formatter) setVulnerabilityData(
	dependency *entities.Dependency, projectSubPath string) *vulnerability.Vulnerability {
	code, filepath, line := file.GetDependencyCodeFilepathAndLine(
		f.GetConfigProjectPath(), projectSubPath, enums.CsProjExt, dependency.Name)
	vuln := f.getDefaultVulnerabilityData()
	vuln.Details = dependency.GetDescription()
	vuln.Code = code
	vuln.File = strings.ReplaceAll(filepath, fmt.Sprintf(enums.FilePathReplace, f.GetAnalysisID()), "")
	vuln.Line = line
	vuln.Severity = dependency.GetSeverity()
	vuln = vulnHash.Bind(vuln)
	return f.SetCommitAuthor(vuln)
}

func (f *Formatter) getDefaultVulnerabilityData() *vulnerability.Vulnerability {
	vuln := &vulnerability.Vulnerability{}
	vuln.SecurityTool = tools.DotnetCli
	vuln.Language = languages.CSharp
	vuln.Confidence = confidence.High
	return vuln
}

func (f *Formatter) checkOutputErrors(output string, err error) (string, error) {
	if err != nil {
		return output, err
	}

	if strings.Contains(output, enums.SolutionNotFound) {
		return output, enums.ErrorSolutionNotFound
	}

	return output, nil
}

func (f *Formatter) isInvalidOutput(output string) bool {
	if strings.Contains(output, "Top-level Package") && strings.Contains(output, "Requested") &&
		strings.Contains(output, "Resolved") && strings.Contains(output, "Severity") {
		return false
	}

	return true
}
