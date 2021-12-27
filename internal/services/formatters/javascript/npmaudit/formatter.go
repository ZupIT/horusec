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

	output, err := f.startNpmAudit(projectSubPath)
	f.SetAnalysisError(err, tools.NpmAudit, output, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.NpmAudit, languages.Javascript)
}

func (f *Formatter) startNpmAudit(projectSubPath string) (string, error) {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.NpmAudit, languages.Javascript)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return output, err
	}

	return output, f.parseOutput(output, projectSubPath)
}

func (f *Formatter) getDockerConfig(projectSubPath string) *docker.AnalysisData {
	analysisData := &docker.AnalysisData{
		CMD:      f.GetConfigCMDByFileExtension(projectSubPath, CMD, "package-lock.json", tools.NpmAudit),
		Language: languages.Javascript,
	}

	return analysisData.SetImage(f.GetCustomImageByLanguage(languages.Javascript), images.Javascript)
}

func (f *Formatter) parseOutput(containerOutput, projectSubPath string) error {
	if err := f.IsNotFoundError(containerOutput); err != nil {
		return err
	}

	output, err := f.newContainerOutputFromString(containerOutput)
	if err != nil {
		return err
	}

	f.processOutput(output, projectSubPath)
	return nil
}

func (f *Formatter) IsNotFoundError(containerOutput string) error {
	if strings.Contains(containerOutput, "ERROR_PACKAGE_LOCK_NOT_FOUND") {
		return errors.New(messages.MsgErrorPacketJSONNotFound)
	}

	return nil
}

func (f *Formatter) newContainerOutputFromString(containerOutput string) (output *npmOutput, err error) {
	if containerOutput == "" {
		logger.LogDebugWithLevel(messages.MsgDebugOutputEmpty, map[string]interface{}{"tool": tools.NpmAudit.ToString()})
		return &npmOutput{}, nil
	}

	return output, json.Unmarshal([]byte(containerOutput), &output)
}

func (f *Formatter) processOutput(output *npmOutput, projectSubPath string) {
	for _, advisory := range output.Advisories {
		advisoryPointer := advisory
		f.AddNewVulnerabilityIntoAnalysis(f.newVulnerability(&advisoryPointer, projectSubPath))
	}
}

func (f *Formatter) newVulnerability(issue *npmIssue, projectSubPath string) *vulnerability.Vulnerability {
	vuln := &vulnerability.Vulnerability{
		File:         f.GetFilepathFromFilename("package-lock.json", projectSubPath),
		SecurityTool: tools.NpmAudit,
		Language:     languages.Javascript,
		Severity:     issue.getSeverity(),
		Details:      issue.Overview,
		Code:         issue.ModuleName,
	}
	vuln.Line = f.getVulnerabilityLineByName(f.getVersionText(issue.getVersion()), vuln.Code, vuln.File)
	return f.SetCommitAuthor(vulnhash.Bind(vuln))
}

func (f *Formatter) getVersionText(version string) string {
	return fmt.Sprintf(`"version": %q`, version)
}

func (f *Formatter) getVulnerabilityLineByName(version, module, filename string) string {
	file, err := os.Open(filepath.Join(f.GetConfigProjectPath(), filename))
	if err != nil {
		return ""
	}

	defer func() {
		logger.LogErrorWithLevel(messages.MsgErrorDeferFileClose, file.Close())
	}()

	return f.getLine(version, module, bufio.NewScanner(file))
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
	return strings.Contains(strings.ToLower(scannerText), strings.ToLower(fmt.Sprintf("%q: {", module)))
}
