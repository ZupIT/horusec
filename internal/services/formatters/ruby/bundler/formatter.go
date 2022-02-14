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
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/utils/file"
	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"
)

// ErrGemLockNotFound occurs when project path does not have the Gemfile.lock file.
//
// nolint: stylecheck
// We actually want that this error message be capitalized since the file name that was
// not found is capitalized.
var ErrGemLockNotFound = errors.New("Gemfile.lock file is required to execute Bundler analysis")

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

	output, err := f.startBundlerAudit(projectSubPath)
	f.SetAnalysisError(err, tools.BundlerAudit, output, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.BundlerAudit, languages.Ruby)
}

func (f *Formatter) startBundlerAudit(projectSubPath string) (string, error) {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.BundlerAudit, languages.Ruby)

	output, err := f.ExecuteContainer(f.getDockerConfig(projectSubPath))
	if err != nil {
		return output, err
	}

	if errGemLock := f.verifyGemLockError(output); errGemLock != nil {
		return output, errGemLock
	}
	err = f.parseOutput(f.removeOutputEsc(output), projectSubPath)
	if err != nil {
		return "", err
	}
	return "", nil
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD: f.AddWorkDirInCmd(
			CMD,
			file.GetSubPathByExtension(f.GetConfigProjectPath(), projectSubPath, "Gemfile.lock"),
			tools.SecurityCodeScan,
		),
		Language: languages.Ruby,
	}

	return analysisData.SetImage(f.GetCustomImageByLanguage(languages.Ruby), images.Ruby)
}

func (f *Formatter) verifyGemLockError(output string) error {
	if strings.Contains(output, `Could not find "Gemfile.lock"`) {
		return ErrGemLockNotFound
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

func (f *Formatter) parseOutput(output, projectSubPath string) error {
	isInvalid, err := f.isValidOutput(output)
	if isInvalid {
		return err
	}

	for _, outputSplit := range strings.Split(output, "Name:") {
		err := f.processOutput(outputSplit, projectSubPath)
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *Formatter) isValidOutput(output string) (bool, error) {
	// If the output does not have the "Name:" string when we split on this string
	// the strings.Split function will return a list with a single element and this
	// single element will be the entire invalid output, so we do this strings.Contains
	// validation to avoid parse an invalid output data.
	if strings.Contains(output, "No vulnerabilities found") || !strings.Contains(output, "Name:") {
		if strings.Contains(output, "No vulnerabilities found") {
			return true, nil
		}
		return true, errors.New("invalid output data")
	}
	return false, nil
}

// nolint: funlen,gocyclo // needs to be bigger
func (f *Formatter) processOutput(outputData, projectSubPath string) error {
	if outputData == "" {
		return nil
	}

	var output bundlerOutput
	for _, value := range strings.Split(outputData, "\r\n") {
		if value == "" || value == "Vulnerabilities found!" {
			continue
		}

		output.setOutputData(&output, value)
	}
	vuln, err := f.newVulnerability(&output, projectSubPath)
	if err != nil {
		return err
	}
	f.AddNewVulnerabilityIntoAnalysis(vuln)
	return err
}

// nolint: funlen // needs to be bigger
func (f *Formatter) newVulnerability(output *bundlerOutput,
	projectSubPath string) (*vulnerability.Vulnerability, error,
) {
	filePath, err := f.GetFilepathFromFilename("Gemfile.lock", projectSubPath)
	if err != nil {
		return nil, err
	}
	vuln := &vulnerability.Vulnerability{
		SecurityTool: tools.BundlerAudit,
		Language:     languages.Ruby,
		Confidence:   confidence.Low,
		Severity:     output.getSeverity(),
		RuleID:       output.Advisory,
		Details:      output.getDetails(),
		File:         filePath,
		Code:         f.GetCodeWithMaxCharacters(output.Name, 0),
	}
	vuln.Line = f.getVulnerabilityLineByName(vuln.Code, vuln.File)
	return f.SetCommitAuthor(vulnhash.Bind(vuln)), err
}

func (f *Formatter) getVulnerabilityLineByName(module, fileName string) string {
	filePath := filepath.Join(f.GetConfigProjectPath(), filepath.Clean(fileName))
	fileExisting, err := os.Open(filePath)
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
