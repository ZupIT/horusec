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

package bundler

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec/internal/utils/file"
	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"

	"github.com/ZupIT/horusec/internal/enums/images"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	errorsEnums "github.com/ZupIT/horusec/internal/enums/errors"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/services/formatters/ruby/bundler/entities"
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
	if f.ToolIsToIgnore(tools.BundlerAudit) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.BundlerAudit.ToString())
		return
	}

	f.SetAnalysisError(f.startBundlerAudit(projectSubPath), tools.BundlerAudit, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.BundlerAudit)
	f.SetToolFinishedAnalysis()
}

func (f *Formatter) startBundlerAudit(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.BundlerAudit)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return err
	}

	if errGemLock := f.verifyGemLockError(output); errGemLock != nil {
		return errGemLock
	}

	f.parseOutput(f.removeOutputEsc(output))
	return nil
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD: f.AddWorkDirInCmd(CMD, file.GetSubPathByExtension(
			f.GetConfigProjectPath(), projectSubPath, "Gemfile.lock"), tools.SecurityCodeScan),
		Language: languages.Ruby,
	}

	return analysisData.SetData(f.GetCustomImageByLanguage(languages.Ruby), images.Ruby)
}

func (f *Formatter) verifyGemLockError(output string) error {
	if strings.Contains(output, "No such file or directory") && strings.Contains(output, "Errno::ENOENT") {
		return errorsEnums.ErrGemLockNotFound
	}

	return nil
}

func (f *Formatter) removeOutputEsc(output string) string {
	output = strings.ReplaceAll(output, "\u001B[0m", "")
	output = strings.ReplaceAll(output, "\u001B[31m", "")
	output = strings.ReplaceAll(output, "\u001B[32m", "")
	output = strings.ReplaceAll(output, "\u001B[33m", "")
	output = strings.ReplaceAll(output, "\u001B[1m", "")
	return output
}

func (f *Formatter) parseOutput(output string) {
	if strings.Contains(output, "No vulnerabilities found") {
		return
	}

	for _, outputSplit := range strings.Split(output, "Name:") {
		f.setOutput(outputSplit)
	}
}

func (f *Formatter) setOutput(outputSplit string) {
	if outputSplit == "" {
		return
	}

	output := &entities.Output{}
	for _, value := range strings.Split(outputSplit, "\r\n") {
		if value == "" || value == "Vulnerabilities found!" {
			continue
		}

		output.SetOutputData(output, value)
	}

	f.AddNewVulnerabilityIntoAnalysis(f.setVulnerabilityData(output))
}

func (f *Formatter) setVulnerabilityData(output *entities.Output) *vulnerability.Vulnerability {
	vuln := f.getDefaultVulnerabilitySeverity()
	vuln.Confidence = confidence.Low
	vuln.Severity = output.GetSeverity()
	vuln.Details = output.GetDetails()
	vuln.File = f.GetFilepathFromFilename("Gemfile.lock")
	vuln.Code = f.GetCodeWithMaxCharacters(output.Name, 0)
	vuln.Line = f.getVulnerabilityLineByName(vuln.Code, vuln.File)
	vuln = vulnhash.Bind(vuln)
	return f.SetCommitAuthor(vuln)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *vulnerability.Vulnerability {
	vulnerabilitySeverity := &vulnerability.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.BundlerAudit
	vulnerabilitySeverity.Language = languages.Ruby
	return vulnerabilitySeverity
}

func (f *Formatter) getVulnerabilityLineByName(module, fileName string) string {
	fileExisting, err := os.Open(fmt.Sprintf("%s/%s", f.GetConfigProjectPath(), fileName))
	if err != nil {
		return ""
	}

	defer func() {
		logger.LogErrorWithLevel(messages.MsgErrorDeferFileClose, fileExisting.Close())
	}()

	return f.getLine(module, bufio.NewScanner(fileExisting))
}

func (f *Formatter) getLine(module string, scanner *bufio.Scanner) string {
	line := 1

	for scanner.Scan() {
		if strings.Contains(strings.ToLower(scanner.Text()), strings.ToLower(module)) {
			return strconv.Itoa(line)
		}

		line++
	}

	return ""
}
