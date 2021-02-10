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

	fileUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/file"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	hash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	errorsEnums "github.com/ZupIT/horusec/horusec-cli/internal/enums/errors"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters/ruby/bundler/entities"
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
		CMD: f.AddWorkDirInCmd(ImageCmd, fileUtil.GetSubPathByExtension(
			f.GetConfigProjectPath(), projectSubPath, "Gemfile.lock"), tools.SecurityCodeScan),
		Language: languages.Ruby,
	}

	return analysisData.SetData(f.GetToolsConfig()[tools.BundlerAudit].ImagePath, ImageName, ImageTag)
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
	output = strings.ReplaceAll(output, "\u001B[33m", "")
	output = strings.ReplaceAll(output, "\u001B[1m", "")
	return output
}

func (f *Formatter) parseOutput(output string) {
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

func (f *Formatter) setVulnerabilityData(output *entities.Output) *horusec.Vulnerability {
	data := f.getDefaultVulnerabilitySeverity()
	data.Severity = output.GetSeverity()
	data.Details = output.GetDetails()
	data.File = f.GetFilepathFromFilename("Gemfile.lock")
	data.Code = f.GetCodeWithMaxCharacters(output.Name, 0)
	data = hash.Bind(data)
	data.Line = f.getVulnerabilityLineByName(data.Code, data.File)
	return f.SetCommitAuthor(data)
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.BundlerAudit
	vulnerabilitySeverity.Language = languages.Ruby
	return vulnerabilitySeverity
}

func (f *Formatter) getVulnerabilityLineByName(module, file string) string {
	fileExisting, err := os.Open(fmt.Sprintf("%s/%s", f.GetConfigProjectPath(), file))
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
