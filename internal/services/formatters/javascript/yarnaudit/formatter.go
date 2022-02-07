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
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	"github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"
)

type Formatter struct {
	formatters.IService
	modules map[string]bool
}

func NewFormatter(service formatters.IService) formatters.IFormatter {
	return &Formatter{
		IService: service,
		modules:  make(map[string]bool),
	}
}

func (f *Formatter) StartAnalysis(projectSubPath string) {
	if f.ToolIsToIgnore(tools.YarnAudit) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.YarnAudit.ToString())
		return
	}

	output, err := f.startYarnAudit(projectSubPath)
	f.SetAnalysisError(err, tools.YarnAudit, output, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.YarnAudit, languages.Javascript)
}

func (f *Formatter) startYarnAudit(projectSubPath string) (string, error) {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.YarnAudit, languages.Javascript)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return output, err
	}

	return output, f.parseOutput(output, projectSubPath)
}

func (f *Formatter) getDockerConfig(projectSubPath string) *docker.AnalysisData {
	analysisData := &docker.AnalysisData{
		CMD:      f.GetConfigCMDByFileExtension(projectSubPath, CMD, "yarn.lock", tools.YarnAudit),
		Language: languages.Javascript,
	}

	return analysisData.SetImage(f.GetCustomImageByLanguage(languages.Javascript), images.Javascript)
}

func (f *Formatter) parseOutput(containerOutput, projectSubPath string) error {
	if err := f.VerifyErrors(containerOutput); err != nil {
		return err
	}

	output, err := f.newContainerOutputFromString(containerOutput)
	if err != nil {
		return err
	}

	f.processOutput(output, projectSubPath)
	return nil
}

func (f *Formatter) VerifyErrors(containerOutput string) error {
	if f.isNotFoundError(containerOutput) {
		return errors.New(messages.MsgErrorYarnLockNotFound)
	}

	if f.isRunningError(containerOutput) {
		return errors.New(messages.MsgErrorYarnProcess + containerOutput)
	}

	return nil
}

func (f *Formatter) isNotFoundError(containerOutput string) bool {
	return strings.Contains(containerOutput, "ERROR_YARN_LOCK_NOT_FOUND")
}

func (f *Formatter) isRunningError(containerOutput string) bool {
	return strings.Contains(containerOutput, "ERROR_RUNNING_YARN_AUDIT")
}

func (f *Formatter) newContainerOutputFromString(containerOutput string) (output *yarnOutput, err error) {
	if containerOutput == "" {
		logger.LogDebugWithLevel(messages.MsgDebugOutputEmpty,
			map[string]interface{}{"tool": tools.YarnAudit.ToString()},
		)
		return &yarnOutput{}, nil
	}

	return output, json.Unmarshal([]byte(containerOutput), &output)
}

func (f *Formatter) processOutput(output *yarnOutput, projectSubPath string) {
	for _, advisory := range output.Advisories {
		if f.notContainsModule(advisory.ModuleName) {
			advisoryPointer := advisory
			f.AddNewVulnerabilityIntoAnalysis(f.newVulnerability(&advisoryPointer, projectSubPath))
		}
	}
}

func (f *Formatter) newVulnerability(output *issue, projectSubPath string) *vulnerability.Vulnerability {
	vuln := &vulnerability.Vulnerability{
		SecurityTool: tools.YarnAudit,
		Language:     languages.Javascript,
		File:         f.GetFilepathFromFilename("yarn.lock", projectSubPath),
		Severity:     output.getSeverity(),
		RuleID:       strconv.Itoa(output.ID),
		Details:      output.Overview,
		Code:         output.ModuleName,
	}
	vuln.Line = f.getVulnerabilityLineByName(vuln.Code, output.getVersion(), vuln.File)
	return f.SetCommitAuthor(vulnhash.Bind(vuln))
}

func (f *Formatter) getVulnerabilityLineByName(module, version, filename string) string {
	file, err := os.Open(filepath.Join(f.GetConfigProjectPath(), filename))
	if err != nil {
		return ""
	}

	defer func() {
		logger.LogErrorWithLevel(messages.MsgErrorDeferFileClose, file.Close())
	}()

	return f.getLine(module, version, bufio.NewScanner(file))
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
	for _, name := range f.possibleExistingNames(module, version) {
		if strings.Contains(strings.ToLower(scannerText), name) {
			return true
		}
	}

	return false
}

func (f *Formatter) possibleExistingNames(module, version string) []string {
	return []string{
		strings.ToLower(fmt.Sprintf("%s@%s", module, version)),
		strings.ToLower(fmt.Sprintf("%s@~%s", module, version)),
		strings.ToLower(fmt.Sprintf("%s@^%s", module, version)),
	}
}

func (f *Formatter) notContainsModule(module string) bool {
	if f.modules[module] {
		return false
	}

	f.modules[module] = true
	return true
}
