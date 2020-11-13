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

package hcl

import (
	"encoding/json"
	"fmt"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	vulnhash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/analyser/hcl"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
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
	if f.ToolIsToIgnore(tools.TfSec) {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.TfSec.ToString(), logger.DebugLevel)
		return
	}
	err := f.startTfSec(projectSubPath)
	f.SetLanguageIsFinished()
	f.LogAnalysisError(err, tools.TfSec, projectSubPath)
}

func (f *Formatter) startTfSec(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.TfSec)

	output, err := f.ExecuteContainer(f.getConfigData(projectSubPath))
	if err != nil {
		f.SetAnalysisError(err)
		return err
	}

	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.TfSec)
	return f.parseOutput(output)
}

func (f *Formatter) getConfigData(projectSubPath string) *dockerEntities.AnalysisData {
	return &dockerEntities.AnalysisData{
		Image:    ImageName,
		Tag:      ImageTag,
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.TfSec),
		Language: languages.HCL,
	}
}

func (f *Formatter) parseOutput(output string) error {
	var vulnerabilities *hcl.Vulnerabilities

	if err := json.Unmarshal([]byte(output), &vulnerabilities); err != nil {
		if !strings.Contains(output, "panic") {
			f.SetAnalysisError(fmt.Errorf("{HORUSEC_CLI} Error %s", output))
		}

		return err
	}

	f.appendResults(vulnerabilities)
	return nil
}

func (f *Formatter) appendResults(hclVulnerabilities *hcl.Vulnerabilities) {
	for _, result := range hclVulnerabilities.Results {
		hclResult := result
		f.GetAnalysis().AnalysisVulnerabilities = append(f.GetAnalysis().AnalysisVulnerabilities,
			horusec.AnalysisVulnerabilities{
				Vulnerability: *f.setVulnerabilityData(&hclResult),
			})
	}
}

func (f *Formatter) setVulnerabilityData(result *hcl.Result) *horusec.Vulnerability {
	vulnerability := f.getDefaultVulnerabilitySeverity()
	vulnerability.Severity = severity.High
	vulnerability.Details = result.GetDetails()
	vulnerability.Line = result.GetStartLine()
	vulnerability.Code = f.GetCodeWithMaxCharacters(result.GetCode(), 0)
	vulnerability.File = f.RemoveSrcFolderFromPath(result.GetFilename())

	// Set vulnerabilitySeverity.VulnHash value
	vulnerability = vulnhash.Bind(vulnerability)

	return f.setCommitAuthor(vulnerability)
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
	vulnerabilitySeverity.SecurityTool = tools.TfSec
	vulnerabilitySeverity.Language = languages.HCL
	return vulnerabilitySeverity
}
