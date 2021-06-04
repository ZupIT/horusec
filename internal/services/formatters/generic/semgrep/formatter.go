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

package semgrep

import (
	"encoding/json"
	"path/filepath"
	"strconv"

	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"

	"github.com/ZupIT/horusec/internal/enums/images"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/services/formatters/generic/semgrep/entities"
)

type Formatter struct {
	formatters.IService
}

func NewFormatter(service formatters.IService) formatters.IFormatter {
	return &Formatter{
		service,
	}
}

func (f *Formatter) StartAnalysis(projectSubPath string) {
	if f.ToolIsToIgnore(tools.Semgrep) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.Semgrep.ToString())
		return
	}

	f.SetAnalysisError(f.startSemgrep(projectSubPath), tools.SecurityCodeScan, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Semgrep, languages.Generic)
}

func (f *Formatter) startSemgrep(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Semgrep, languages.Generic)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return err
	}

	return f.parseOutput(output)
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(CMD, projectSubPath, tools.Semgrep),
		Language: languages.Generic,
	}

	return analysisData.SetData(f.GetCustomImageByLanguage(languages.Generic), images.Generic)
}

func (f *Formatter) parseOutput(output string) error {
	var analysis *entities.Analysis

	if err := json.Unmarshal([]byte(output), &analysis); err != nil {
		return err
	}

	for _, result := range analysis.Results {
		item := result
		f.AddNewVulnerabilityIntoAnalysis(f.setVulnerabilityData(&item))
	}

	return nil
}

func (f *Formatter) setVulnerabilityData(result *entities.Result) *vulnerability.Vulnerability {
	data := f.getDefaultVulnerabilityData()
	data.Details = result.Extra.Message
	data.Severity = f.getSeverity(result.Extra.Severity)
	data.Line = strconv.Itoa(result.Start.Line)
	data.Column = strconv.Itoa(result.Start.Col)
	data.File = result.Path
	data.Code = f.GetCodeWithMaxCharacters(result.Extra.Code, 0)
	data.Language = f.getLanguageByFile(result.Path)
	data = vulnhash.Bind(data)
	return f.SetCommitAuthor(data)
}

func (f *Formatter) getDefaultVulnerabilityData() *vulnerability.Vulnerability {
	vulnerabilitySeverity := &vulnerability.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.Semgrep
	return vulnerabilitySeverity
}

func (f *Formatter) getLanguageByFile(file string) languages.Language {
	languagesMap := f.getLanguagesMap()
	return languagesMap[f.getExtension(file)]
}

func (f *Formatter) getExtension(file string) string {
	ext := filepath.Ext(file)

	for _, item := range f.getExtensionList() {
		if item == ext {
			return ext
		}
	}

	return ""
}

func (f *Formatter) getLanguagesMap() map[string]languages.Language {
	return map[string]languages.Language{
		".go":   languages.Go,
		".java": languages.Java,
		".js":   languages.Javascript,
		".tsx":  languages.Typescript,
		".ts":   languages.Typescript,
		".py":   languages.Python,
		".rb":   languages.Ruby,
		".c":    languages.C,
		".html": languages.HTML,
		"":      languages.Unknown,
	}
}

func (f *Formatter) getExtensionList() []string {
	return []string{
		".go",
		".java",
		".js",
		".tsx",
		".ts",
		".py",
		".rb",
		".c",
		".html",
	}
}

func (f *Formatter) getSeverity(resultSeverity string) severities.Severity {
	switch resultSeverity {
	case "ERROR":
		return severities.High
	case "WARNING":
		return severities.Medium
	}

	return severities.Low
}
