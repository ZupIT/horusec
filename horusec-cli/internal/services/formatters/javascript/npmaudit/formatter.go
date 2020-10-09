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
	vulnhash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	"os"
	"strconv"
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/analyser/javascript/npm"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	fileUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/file"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
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
	err := f.startNpmAuditAnalysis(projectSubPath)
	f.LogAnalysisError(err, tools.NpmAudit, projectSubPath)
	f.SetLanguageIsFinished()
}

func (f *Formatter) startNpmAuditAnalysis(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.NpmAudit)

	output, err := f.ExecuteContainer(f.getConfigDataNpm(projectSubPath))
	if err != nil {
		f.SetAnalysisError(err)
		return err
	}

	f.SetAnalysisError(f.parseOutput(output))
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.NpmAudit)
	return nil
}

func (f *Formatter) parseOutput(containerOutput string) error {
	if f.IsNotFoundError(containerOutput) {
		f.setNotFoundError()
		return nil
	}

	output, err := f.newContainerOutputFromString(containerOutput)
	if err != nil {
		return err
	}

	f.processOutput(output)
	return nil
}

func (f *Formatter) newContainerOutputFromString(containerOutput string) (output *npm.Output, err error) {
	if containerOutput == "" {
		logger.LogDebugWithLevel(messages.MsgDebugOutputEmpty, logger.DebugLevel,
			map[string]interface{}{"tool": tools.NpmAudit.ToString()})
		return &npm.Output{}, nil
	}

	err = json.Unmarshal([]byte(containerOutput), &output)
	if err != nil {
		logger.LogErrorWithLevel(f.GetAnalysisIDErrorMessage(tools.NpmAudit, containerOutput), err, logger.ErrorLevel)
	}

	return output, err
}

func (f *Formatter) setVulnerabilitySeverityData(output *npm.Issue) (data *horusec.Vulnerability) {
	data = f.getDefaultVulnerabilitySeverity()
	data.Severity = output.GetSeverity()
	data.Details = output.Overview
	data.Code = output.ModuleName
	data.Line = f.getVulnerabilityLineByName(fmt.Sprintf(`"version": "%s"`, output.GetVersion()), data.Code, data.File)
	data = vulnhash.Bind(data)
	return f.setCommitAuthor(data)
}

func (f *Formatter) setCommitAuthor(vulnerability *horusec.Vulnerability) *horusec.Vulnerability {
	commitAuthor := f.GetCommitAuthor(vulnerability.Line, vulnerability.File)

	vulnerability.CommitAuthor = commitAuthor.Author
	vulnerability.CommitHash = commitAuthor.CommitHash
	vulnerability.CommitDate = commitAuthor.Date
	vulnerability.CommitEmail = commitAuthor.Email
	vulnerability.CommitMessage = commitAuthor.Message

	return vulnerability
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.File = "package-lock.json"
	vulnerabilitySeverity.SecurityTool = tools.NpmAudit
	vulnerabilitySeverity.Language = languages.Javascript
	return vulnerabilitySeverity
}

func (f *Formatter) IsNotFoundError(containerOutput string) bool {
	return strings.Contains(containerOutput, "ERROR_PACKAGE_LOCK_NOT_FOUND")
}

func (f *Formatter) setNotFoundError() {
	err := errors.New(messages.MsgErrorPacketJSONNotFound)
	f.SetAnalysisError(err)
}

func (f *Formatter) processOutput(output *npm.Output) {
	for _, advisory := range output.Advisories {
		value := advisory
		vulnerability := f.setVulnerabilitySeverityData(&value)
		f.GetAnalysis().AnalysisVulnerabilities = append(f.GetAnalysis().AnalysisVulnerabilities,
			horusec.AnalysisVulnerabilities{
				Vulnerability: *vulnerability,
			})
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

func (f *Formatter) getConfigDataNpm(projectSubPath string) *dockerEntities.AnalysisData {
	return &dockerEntities.AnalysisData{
		Image:    ImageName,
		Tag:      ImageTag,
		CMD:      f.getConfigCMD(projectSubPath),
		Language: languages.Javascript,
	}
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
