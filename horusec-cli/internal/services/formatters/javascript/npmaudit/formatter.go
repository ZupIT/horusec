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
	fileUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/file"
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
	if f.ToolIsToIgnore(tools.NpmAudit) {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored+tools.NpmAudit.ToString(), logger.DebugLevel)
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

func (f *Formatter) parseOutput(containerOutput string) error {
	if f.IsNotFoundError(containerOutput) {
		return f.notFoundError()
	}

	output, err := f.newContainerOutputFromString(containerOutput)
	if err != nil {
		return err
	}

	f.processOutput(output)
	return nil
}

func (f *Formatter) newContainerOutputFromString(containerOutput string) (output *entities.Output, err error) {
	if containerOutput == "" {
		logger.LogDebugWithLevel(messages.MsgDebugOutputEmpty, logger.DebugLevel,
			map[string]interface{}{"tool": tools.NpmAudit.ToString()})
		return &entities.Output{}, nil
	}

	err = json.Unmarshal([]byte(containerOutput), &output)
	if err != nil {
		logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.NpmAudit, containerOutput), err, logger.ErrorLevel)
	}

	return output, err
}

func (f *Formatter) setVulnerabilitySeverityData(output *entities.Issue) (data *horusec.Vulnerability) {
	data = f.getDefaultVulnerabilitySeverity()
	data.Severity = output.GetSeverity()
	data.Details = output.Overview
	data.Code = output.ModuleName
	data.Line = f.getVulnerabilityLineByName(fmt.Sprintf(`"version": "%s"`, output.GetVersion()), data.Code, data.File)
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

func (f *Formatter) IsNotFoundError(containerOutput string) bool {
	return strings.Contains(containerOutput, "ERROR_PACKAGE_LOCK_NOT_FOUND")
}

func (f *Formatter) notFoundError() error {
	return errors.New(messages.MsgErrorPacketJSONNotFound)
}

func (f *Formatter) processOutput(output *entities.Output) {
	for _, advisory := range output.Advisories {
		advisoryPointer := advisory
		f.AddNewVulnerabilityIntoAnalysis(f.setVulnerabilitySeverityData(&advisoryPointer))
	}
}

func (f *Formatter) getVulnerabilityLineByName(line, module, file string) string {
	path := fmt.Sprintf("%s/%s", f.GetConfigProjectPath(), file)
	fileExisting, err := os.Open(path)
	if err != nil {
		return ""
	}

	defer func() {
		logger.LogErrorWithLevel(messages.MsgErrorDeferFileClose, fileExisting.Close(), logger.ErrorLevel)
	}()

	scanner := bufio.NewScanner(fileExisting)
	return f.getLine(line, module, scanner)
}

func (f *Formatter) getLine(name, module string, scanner *bufio.Scanner) string {
	line := 1
	isFoundModule := false

	for scanner.Scan() {
		scannerText := scanner.Text()
		if isModuleInScannerText(isFoundModule, module, scannerText) {
			isFoundModule = true
		} else if isFoundModule && strings.Contains(strings.ToLower(scannerText), strings.ToLower(name)) {
			return strconv.Itoa(line)
		}
		line++
	}
	return ""
}

func isModuleInScannerText(isFoundModule bool, module, scannerText string) bool {
	packageModuleName := fmt.Sprintf(`"%s": {`, module)
	return !isFoundModule && strings.Contains(strings.ToLower(scannerText), strings.ToLower(packageModuleName))
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.getConfigCMD(projectSubPath),
		Language: languages.Javascript,
	}

	return analysisData.SetFullImagePath(f.GetToolsConfig()[tools.NpmAudit].ImagePath, ImageName, ImageTag)
}

func (f *Formatter) getConfigCMD(projectSubPath string) string {
	projectPath := f.GetConfigProjectPath()

	newProjectSubPath := fileUtil.GetSubPathByExtension(projectPath, projectSubPath, "package-lock.json")
	if newProjectSubPath != "" {
		return f.AddWorkDirInCmd(ImageCmd, newProjectSubPath, tools.NpmAudit)
	}

	newProjectSubPath = fileUtil.GetSubPathByExtension(projectPath, projectSubPath, "yarn.lock")
	if newProjectSubPath != "" {
		return f.AddWorkDirInCmd(ImageCmd, newProjectSubPath, tools.NpmAudit)
	}

	return f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.NpmAudit)
}
