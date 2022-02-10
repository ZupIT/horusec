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

package sobelow

import (
	"errors"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"

	"github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/formatters"
	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"
)

const (
	replaceDefaultMessage = "Checking Sobelow version..."

	// nolint: lll
	notAPhoenixApplication = "project not appear to be a Phoenix application. If this is an Umbrella application, each application should be scanned separately"
)

var ErrorNotAPhoenixApplication = errors.New(notAPhoenixApplication)

type Formatter struct {
	formatters.IService
}

func NewFormatter(service formatters.IService) *Formatter {
	return &Formatter{
		service,
	}
}

func (f *Formatter) StartAnalysis(projectSubPath string) {
	if f.ToolIsToIgnore(tools.Sobelow) || f.IsDockerDisabled() {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.Sobelow.ToString())
		return
	}

	output, err := f.startSobelow(projectSubPath)
	f.SetAnalysisError(err, tools.Sobelow, output, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.Sobelow, languages.Elixir)
}

func (f *Formatter) startSobelow(projectSubPath string) (string, error) {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.Sobelow, languages.Elixir)

	output, err := f.ExecuteContainer(f.getConfigData(projectSubPath))
	if err != nil {
		return output, err
	}

	if strings.Contains(output, notAPhoenixApplication) {
		return output, ErrorNotAPhoenixApplication
	}

	f.parseOutput(output, projectSubPath)
	return output, nil
}

func (f *Formatter) getConfigData(projectSubPath string) *docker.AnalysisData {
	analysisData := &docker.AnalysisData{
		CMD:      f.GetConfigCMDByFileExtension(projectSubPath, CMD, "mix.lock", tools.Sobelow),
		Language: languages.Elixir,
	}

	return analysisData.SetImage(f.GetCustomImageByLanguage(languages.Elixir), images.Elixir)
}

// nolint:funlen // needs to be bigger
func (f *Formatter) parseOutput(output, projectSubPath string) {
	output = strings.ReplaceAll(strings.ReplaceAll(output, replaceDefaultMessage, ""), "\r", "")

	for _, value := range strings.Split(output, "\n") {
		if value == "" {
			continue
		}

		if data := f.newOutput(value); data != nil {
			vuln, err := f.newVulnerability(data, projectSubPath)
			if err != nil {
				f.SetAnalysisError(err, tools.Sobelow, err.Error(), "")
				continue
			}
			f.AddNewVulnerabilityIntoAnalysis(vuln)
		}
	}
}

func (f *Formatter) newOutput(output string) *sobelowOutput {
	indexFirstColon := strings.Index(output, ":")
	indexLastColon := strings.LastIndex(output, ":")
	indexTrace := strings.LastIndex(output, "-")

	if !strings.Contains(output, "[+]\u001B[0m") {
		return nil
	}

	return &sobelowOutput{
		Title: strings.TrimSpace(output[indexFirstColon+1 : indexTrace]),
		File:  strings.TrimSpace(output[indexTrace+1 : indexLastColon]),
		Line:  strings.TrimSpace(output[indexLastColon+1:]),
	}
}

func (f *Formatter) newVulnerability(output *sobelowOutput,
	projectSubPath string) (*vulnerability.Vulnerability, error,
) {
	filePath, err := f.GetFilepathFromFilename(output.File, projectSubPath)
	if err != nil {
		return nil, err
	}
	vuln := &vulnerability.Vulnerability{
		SecurityTool: tools.Sobelow,
		Language:     languages.Elixir,
		Severity:     severities.Unknown,
		Details:      output.Title,
		File:         filePath,
		Line:         output.Line,
	}
	return f.SetCommitAuthor(vulnhash.Bind(vuln)), err
}
