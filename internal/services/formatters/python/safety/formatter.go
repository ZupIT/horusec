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

package safety

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/services/formatters/python/safety/entities"
	"github.com/ZupIT/horusec/internal/utils/file"
	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"
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
	if f.ToolIsToIgnore(tools.Safety) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.Safety.ToString())
		return
	}

	output, err := f.startSafety(projectSubPath)
	f.SetAnalysisError(err, tools.Safety, output, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Safety, languages.Python)
}

func (f *Formatter) startSafety(projectSubPath string) (string, error) {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Safety, languages.Python)
	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return output, err
	}
	return "", f.parseOutput(output, projectSubPath)
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD: f.AddWorkDirInCmd(CMD, file.GetSubPathByExtension(
			f.GetConfigProjectPath(), projectSubPath, "requirements.txt"), tools.Safety),
		Language: languages.Python,
	}

	return analysisData.SetImage(f.GetCustomImageByLanguage(languages.Python), images.Python)
}

func (f *Formatter) parseOutput(output, projectSubPath string) error {
	if output == "" {
		logger.LogDebugWithLevel(messages.MsgDebugOutputEmpty,
			map[string]interface{}{"tool": tools.Safety.ToString()})
		return nil
	}
	if len(output) >= 19 && strings.EqualFold(output[:19], "ERROR_REQ_NOT_FOUND") {
		return errors.New(messages.MsgErrorNotFoundRequirementsTxt)
	}
	safetyOutput, err := f.parseOutputToSafetyOutput(output)
	if err != nil {
		return err
	}
	f.setSafetyOutPutInHorusecAnalysis(safetyOutput.Issues, projectSubPath)
	return nil
}

func (f *Formatter) parseOutputToSafetyOutput(output string) (safetyOutput entities.SafetyOutput, err error) {
	err = json.Unmarshal([]byte(output), &safetyOutput)
	return safetyOutput, err
}

func (f *Formatter) setSafetyOutPutInHorusecAnalysis(issues []entities.Issue, projectSubPath string) {
	for index := range issues {
		vuln, err := f.setupVulnerabilitiesSeveritiesSafety(issues, index, projectSubPath)
		if err != nil {
			f.SetAnalysisError(err, tools.NpmAudit, err.Error(), "")
			continue
		}
		f.AddNewVulnerabilityIntoAnalysis(vuln)
	}
}

func (f *Formatter) setupVulnerabilitiesSeveritiesSafety(
	issues []entities.Issue, index int, projectSubPath string) (*vulnerability.Vulnerability, error) {
	lineContent := fmt.Sprintf("%s=%s", issues[index].Dependency, issues[index].InstalledVersion)
	vuln, err := f.getDefaultVulnerabilitySeverityInSafety(projectSubPath)
	if err != nil {
		return nil, err
	}
	vuln.Details = issues[index].Description
	vuln.Code = f.GetCodeWithMaxCharacters(issues[index].Dependency, 0)
	vuln.Line = f.getVulnerabilityLineByName(lineContent, vuln.File)
	vuln = vulnhash.Bind(vuln)
	return f.SetCommitAuthor(vuln), err
}

func (f *Formatter) getVulnerabilityLineByName(line, fileName string) string {
	path := filepath.Join(f.GetConfigProjectPath(), filepath.Clean(fileName))
	fileOpened, err := os.Open(path)
	if err != nil {
		return "-"
	}

	defer func() {
		logger.LogErrorWithLevel(messages.MsgErrorDeferFileClose, fileOpened.Close())
	}()
	scanner := bufio.NewScanner(fileOpened)
	return f.getLine(line, scanner)
}

func (f *Formatter) getLine(name string, scanner *bufio.Scanner) string {
	line := 1
	for scanner.Scan() {
		if strings.Contains(strings.ToLower(scanner.Text()), strings.ToLower(name)) {
			return strconv.Itoa(line)
		}

		line++
	}

	return "-"
}

// nolint: funlen,lll // needs to be bigger
func (f *Formatter) getDefaultVulnerabilitySeverityInSafety(projectSubPath string) (*vulnerability.Vulnerability, error) {
	vulnerabilitySeverity := &vulnerability.Vulnerability{}
	vulnerabilitySeverity.Language = languages.Python
	vulnerabilitySeverity.Severity = severities.High
	vulnerabilitySeverity.SecurityTool = tools.Safety
	vulnerabilitySeverity.Confidence = "-"
	vulnerabilitySeverity.Column = "0"
	filePath, err := f.GetFilepathFromFilename("requirements.txt", projectSubPath)
	if err != nil {
		return nil, err
	}
	vulnerabilitySeverity.File = filePath
	return vulnerabilitySeverity, err
}
