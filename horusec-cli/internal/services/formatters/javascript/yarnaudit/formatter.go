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

package yarnaudit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/javascript/yarnaudit/entities"

	vulnhash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/javascript/npmaudit"
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
	if f.ToolIsToIgnore(tools.YarnAudit) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.YarnAudit.ToString())
		return
	}

	f.SetAnalysisError(f.startYarnAudit(projectSubPath), tools.YarnAudit, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.YarnAudit)
	f.SetToolFinishedAnalysis()
}

func (f *Formatter) startYarnAudit(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.YarnAudit)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return err
	}

	return f.parseOutput(output)
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.GetConfigCMDYarnOrNpmAudit(projectSubPath, ImageCmd, tools.YarnAudit),
		Language: languages.Javascript,
	}

	return analysisData.SetFullImagePath(f.GetToolsConfig()[tools.NpmAudit].ImagePath,
		npmaudit.ImageName, npmaudit.ImageTag)
}

func (f *Formatter) parseOutput(containerOutput string) error {
	if err := f.VerifyErrors(containerOutput); err != nil {
		return err
	}

	output, err := f.newContainerOutputFromString(containerOutput)
	if err != nil {
		return err
	}

	f.processOutput(output)
	return nil
}

func (f *Formatter) VerifyErrors(containerOutput string) error {
	if f.IsNotFoundError(containerOutput) {
		return errors.New(messages.MsgErrorYarnLockNotFound)
	}

	if f.IsRunningError(containerOutput) {
		return errors.New(messages.MsgErrorYarnProcess + containerOutput)
	}

	return nil
}

func (f *Formatter) IsNotFoundError(containerOutput string) bool {
	return strings.Contains(containerOutput, "ERROR_YARN_LOCK_NOT_FOUND")
}

func (f *Formatter) IsRunningError(containerOutput string) bool {
	return strings.Contains(containerOutput, "ERROR_RUNNING_YARN_AUDIT")
}

func (f *Formatter) newContainerOutputFromString(containerOutput string) (output *entities.Output, err error) {
	if containerOutput == "" {
		logger.LogDebugWithLevel(messages.MsgDebugOutputEmpty,
			map[string]interface{}{"tool": tools.YarnAudit.ToString()})
		return &entities.Output{}, nil
	}

	if err = json.Unmarshal([]byte(containerOutput), &output); err != nil {
		logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.YarnAudit, containerOutput), err)
	}

	return output, err
}

func (f *Formatter) processOutput(output *entities.Output) {
	for _, advisory := range output.Advisories {
		advisoryPointer := advisory
		f.AddNewVulnerabilityIntoAnalysis(f.setVulnerabilitySeverityData(&advisoryPointer))
	}
}

func (f *Formatter) setVulnerabilitySeverityData(output *entities.Issue) *horusec.Vulnerability {
	data := f.getDefaultVulnerabilitySeverity()
	data.Severity = output.GetSeverity()
	data.Details = output.Overview
	data.Code = output.ModuleName
	data.Line = f.getVulnerabilityLineByName(data.Code, output.GetVersion(), data.File)
	data = vulnhash.Bind(data)
	return f.SetCommitAuthor(data)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.YarnAudit
	vulnerabilitySeverity.Language = languages.Javascript
	vulnerabilitySeverity.File = f.GetFilepathFromFilename("yarn.lock")
	return vulnerabilitySeverity
}

func (f *Formatter) getVulnerabilityLineByName(module, version, file string) string {
	fileExisting, err := os.Open(fmt.Sprintf("%s/%s", f.GetConfigProjectPath(), file))
	if err != nil {
		return ""
	}

	defer func() {
		logger.LogErrorWithLevel(messages.MsgErrorDeferFileClose, fileExisting.Close())
	}()

	return f.getLine(module, version, bufio.NewScanner(fileExisting))
}

func (f *Formatter) getLine(module, version string, scanner *bufio.Scanner) string {
	line := 1

	for scanner.Scan() {
		if f.validateIfExistNameInScannerText(scanner.Text(), module, version) {
			return strconv.Itoa(line)
		}

		line++
	}

	return ""
}

func (f *Formatter) validateIfExistNameInScannerText(scannerText, module, version string) bool {
	for _, name := range f.mapPossibleExistingNames(module, version) {
		if strings.Contains(strings.ToLower(scannerText), name) {
			return true
		}
	}

	return false
}

func (f *Formatter) mapPossibleExistingNames(module, version string) []string {
	return []string{
		strings.ToLower(fmt.Sprintf("%s@%s", module, version)),
		strings.ToLower(fmt.Sprintf("%s@~%s", module, version)),
		strings.ToLower(fmt.Sprintf("%s@^%s", module, version)),
	}
}
