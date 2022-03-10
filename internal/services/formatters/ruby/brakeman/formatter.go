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

package brakeman

import (
	"encoding/json"
	"errors"
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
	fileutils "github.com/ZupIT/horusec/internal/utils/file"
	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"
)

const (
	defaultOutputMaxCharacters = 45

	// notFoundError is the error returned by brakeman when the path
	// analyzed is not a Rails project.
	notFoundError = "please supply the path to a rails application"
)

var ErrNotFoundRailsProject = errors.New(messages.MsgWarnBrakemanNotRubyOnRailsProject)

type Formatter struct {
	formatters.IService
}

func NewFormatter(service formatters.IService) *Formatter {
	return &Formatter{
		service,
	}
}

func (f *Formatter) StartAnalysis(projectSubPath string) {
	if f.ToolIsToIgnore(tools.Brakeman) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.Brakeman.ToString())
		return
	}

	output, err := f.startBrakeman(projectSubPath)
	f.SetAnalysisError(err, tools.Brakeman, output, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Brakeman, languages.Ruby)
}

func (f *Formatter) startBrakeman(projectSubPath string) (string, error) {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Brakeman, languages.Ruby)
	dockerConfig, err := f.getDockerConfig(projectSubPath)
	if err != nil {
		return "", err
	}
	output, err := f.ExecuteContainer(dockerConfig)
	if err != nil {
		return output, err
	}

	return output, f.parseOutput(output, projectSubPath)
}

func (f *Formatter) parseOutput(containerOutput, projectSubPath string) error {
	if containerOutput == "" {
		return nil
	}

	brakemanOutput, err := f.newContainerOutputFromString(containerOutput)
	if err != nil {
		return err
	}

	f.addVulnIntoAnalysis(brakemanOutput, projectSubPath)

	return nil
}

func (f *Formatter) addVulnIntoAnalysis(brakemanOutput brakemanOutput, projectSubPath string) {
	for _, warning := range brakemanOutput.Warnings {
		value := warning
		vuln, err := f.newVulnerability(&value, projectSubPath)
		if err != nil {
			f.SetAnalysisError(err, tools.Brakeman, err.Error(), "")
			continue
		}
		f.AddNewVulnerabilityIntoAnalysis(vuln)
	}
}

func (f *Formatter) newContainerOutputFromString(containerOutput string) (output brakemanOutput, err error) {
	if f.isNotFoundRailsProject(containerOutput) {
		return brakemanOutput{}, ErrNotFoundRailsProject
	}

	err = json.Unmarshal([]byte(containerOutput), &output)
	return output, err
}

// nolint: funlen // needs to be bigger
func (f *Formatter) newVulnerability(output *warning, projectSubPath string) (*vulnerability.Vulnerability, error) {
	filePath, err := f.GetFilepathFromFilename(filepath.FromSlash(output.File), projectSubPath)
	if err != nil {
		return nil, err
	}
	vuln := &vulnerability.Vulnerability{
		SecurityTool: tools.Brakeman,
		Language:     languages.Ruby,
		Severity:     output.getSeverity(),
		Confidence:   output.getConfidence(),
		RuleID:       strconv.Itoa(output.WarningCode),
		Details:      output.getDetails(),
		Line:         output.getLine(),
		File:         filePath,
		Code:         f.GetCodeWithMaxCharacters(output.Code, 0),
	}

	return f.SetCommitAuthor(vulnhash.Bind(vuln)), err
}

func (f *Formatter) getDockerConfig(projectSubPath string) (*docker.AnalysisData, error) {
	subpath, err := fileutils.GetSubPathByFilename(f.GetConfigProjectPath(), projectSubPath, "Gemfile")
	if err != nil {
		return nil, err
	}
	analysisData := &docker.AnalysisData{
		CMD: f.AddWorkDirInCmd(
			CMD,
			subpath,
			tools.Brakeman,
		),
		Language: languages.Ruby,
	}

	return analysisData.SetImage(f.GetCustomImageByLanguage(languages.Ruby), images.Ruby), err
}

func (f *Formatter) isNotFoundRailsProject(output string) bool {
	lowerOutput := strings.ToLower(output)
	if len(lowerOutput) >= defaultOutputMaxCharacters {
		return strings.Contains(lowerOutput[:45], notFoundError)
	}
	return false
}
