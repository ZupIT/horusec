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

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	hash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/generic/semgrep/entities"
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
	if f.ToolIsToIgnore(tools.Semgrep) {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored+tools.Semgrep.ToString(), logger.DebugLevel)
		return
	}

	f.SetAnalysisError(f.startSemgrep(projectSubPath), tools.SecurityCodeScan, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Semgrep)
	f.SetToolFinishedAnalysis()
}

func (f *Formatter) startSemgrep(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Semgrep)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return err
	}

	return f.parseOutput(output)
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	return &dockerEntities.AnalysisData{
		Image:    ImageName,
		Tag:      ImageTag,
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.Semgrep),
		Language: languages.Generic,
	}
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

func (f *Formatter) setVulnerabilityData(result *entities.Result) *horusec.Vulnerability {
	data := f.getDefaultVulnerabilityData()
	data.Details = result.Extra.Message
	data.Severity = f.getSeverity(result.Extra.Severity)
	data.Line = strconv.Itoa(result.Start.Line)
	data.Column = strconv.Itoa(result.Start.Col)
	data.File = result.Path
	data.Code = f.GetCodeWithMaxCharacters(result.Extra.Code, 0)
	data.Language = f.getLanguageByFile(result.Path)
	data = hash.Bind(data)
	return f.SetCommitAuthor(data)
}

func (f *Formatter) getDefaultVulnerabilityData() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
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
		".tsx":  languages.TypeScript,
		".ts":   languages.TypeScript,
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

func (f *Formatter) getSeverity(resultSeverity string) severity.Severity {
	switch resultSeverity {
	case "ERROR":
		return severity.High
	case "WARNING":
		return severity.Medium
	}

	return severity.Low
}
