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

package npmaudit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	hash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/javascript/npmaudit/entities"
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
	if f.ToolIsToIgnore(tools.NpmAudit) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.NpmAudit.ToString())
		return
	}

	f.SetAnalysisError(f.startNpmAudit(projectSubPath), tools.NpmAudit, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.NpmAudit)
	f.SetToolFinishedAnalysis()
}

func (f *Formatter) startNpmAudit(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.NpmAudit)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return err
	}

	return f.parseOutput(output)
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.GetConfigCMDYarnOrNpmAudit(projectSubPath, ImageCmd, tools.NpmAudit),
		Language: languages.Javascript,
	}

	return analysisData.SetFullImagePath(
		f.GetToolsConfig()[tools.NpmAudit].ImagePath, ImageRepository, ImageName, ImageTag)
}

func (f *Formatter) parseOutput(containerOutput string) error {
	if err := f.IsNotFoundError(containerOutput); err != nil {
		return err
	}

	output, err := f.newContainerOutputFromString(containerOutput)
	if err != nil {
		return err
	}

	f.processOutput(output)
	return nil
}

func (f *Formatter) IsNotFoundError(containerOutput string) error {
	if strings.Contains(containerOutput, "ERROR_PACKAGE_LOCK_NOT_FOUND") {
		return errors.New(messages.MsgErrorPacketJSONNotFound)
	}

	return nil
}

func (f *Formatter) newContainerOutputFromString(containerOutput string) (output *entities.Output, err error) {
	if containerOutput == "" {
		logger.LogDebugWithLevel(messages.MsgDebugOutputEmpty, map[string]interface{}{"tool": tools.NpmAudit.ToString()})
		return &entities.Output{}, nil
	}

	if err = json.Unmarshal([]byte(containerOutput), &output); err != nil {
		logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.NpmAudit, containerOutput), err)
	}

	return output, err
}

func (f *Formatter) processOutput(output *entities.Output) {
	for _, advisory := range output.Advisories {
		advisoryPointer := advisory
		f.AddNewVulnerabilityIntoAnalysis(f.setVulnerabilitySeverityData(&advisoryPointer))
	}
}

func (f *Formatter) setVulnerabilitySeverityData(issue *entities.Issue) (data *horusec.Vulnerability) {
	data = f.getDefaultVulnerabilitySeverity()
	data.Severity = issue.GetSeverity()
	data.Details = issue.Overview
	data.Code = issue.ModuleName
	data.Line = f.getVulnerabilityLineByName(f.getVersionText(issue.GetVersion()), data.Code, data.File)
	data = hash.Bind(data)
	return f.SetCommitAuthor(data)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.File = f.GetFilepathFromFilename("package-lock.json")
	vulnerabilitySeverity.SecurityTool = tools.NpmAudit
	vulnerabilitySeverity.Language = languages.Javascript
	return vulnerabilitySeverity
}

func (f *Formatter) getVersionText(version string) string {
	return fmt.Sprintf(`"version": "%s"`, version)
}

func (f *Formatter) getVulnerabilityLineByName(version, module, file string) string {
	fileExisting, err := os.Open(fmt.Sprintf("%s/%s", f.GetConfigProjectPath(), file))
	if err != nil {
		return ""
	}

	defer func() {
		logger.LogErrorWithLevel(messages.MsgErrorDeferFileClose, fileExisting.Close())
	}()

	return f.getLine(version, module, bufio.NewScanner(fileExisting))
}

func (f *Formatter) getLine(version, module string, scanner *bufio.Scanner) string {
	foundModule := false
	line := 1

	for scanner.Scan() {
		if f.isModuleInScannerText(module, scanner.Text()) {
			foundModule = true
			continue
		}

		if foundModule && strings.Contains(strings.ToLower(scanner.Text()), strings.ToLower(version)) {
			return strconv.Itoa(line)
		}
		line++
	}
	return ""
}

func (f *Formatter) isModuleInScannerText(module, scannerText string) bool {
	return strings.Contains(strings.ToLower(scannerText), strings.ToLower(fmt.Sprintf(`"%s": {`, module)))
}
