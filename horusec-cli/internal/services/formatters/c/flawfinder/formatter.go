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

package flawfinder

import (
	"fmt"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/analyser/c"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	fileUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/file"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	vulnhash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"github.com/gocarina/gocsv"
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
	if f.ToolIsToIgnore(tools.FlawFinder) {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored+tools.FlawFinder.ToString(), logger.DebugLevel)
		return
	}

	err := f.startFlawFinder(projectSubPath)
	f.SetLanguageIsFinished()
	f.LogAnalysisError(err, tools.FlawFinder, projectSubPath)
}

func (f *Formatter) startFlawFinder(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.FlawFinder)

	output, err := f.ExecuteContainer(f.getConfigData(projectSubPath))
	if err != nil {
		f.SetAnalysisError(err)
		return err
	}

	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.FlawFinder)
	return f.parseOutput(output)
}

func (f *Formatter) getConfigData(projectSubPath string) *dockerEntities.AnalysisData {
	return &dockerEntities.AnalysisData{
		Image:    ImageName,
		Tag:      ImageTag,
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.FlawFinder),
		Language: languages.C,
	}
}

func (f *Formatter) parseOutput(output string) error {
	var results []c.Result

	if err := gocsv.UnmarshalString(output, &results); err != nil {
		f.SetAnalysisError(fmt.Errorf("{HORUSEC_CLI} Error %s", output))
		return err
	}

	f.appendResults(results)
	return nil
}

func (f *Formatter) appendResults(results []c.Result) {
	for _, result := range results {
		flawFinderResult := result
		f.GetAnalysis().AnalysisVulnerabilities = append(f.GetAnalysis().AnalysisVulnerabilities,
			horusec.AnalysisVulnerabilities{
				Vulnerability: *f.setVulnerabilityData(&flawFinderResult),
			})
	}
}

func (f *Formatter) setVulnerabilityData(result *c.Result) *horusec.Vulnerability {
	vulnerability := f.getDefaultVulnerabilitySeverity()
	vulnerability.Severity = result.GetSeverity()
	vulnerability.Details = result.GetDetails()
	vulnerability.Line = result.Line
	vulnerability.Column = result.Column
	vulnerability.Code = f.GetCodeWithMaxCharacters(result.Context, 0)
	vulnerability.File = result.GetFilename()
	vulnerability = vulnhash.Bind(vulnerability)

	return f.setCommitAuthor(vulnerability)
}

func (f *Formatter) setCommitAuthor(vulnerability *horusec.Vulnerability) *horusec.Vulnerability {
	commitAuthor := f.GetCommitAuthor(vulnerability.Line, f.getFilePathFromPackageName(vulnerability.File))

	vulnerability.CommitAuthor = commitAuthor.Author
	vulnerability.CommitHash = commitAuthor.CommitHash
	vulnerability.CommitDate = commitAuthor.Date
	vulnerability.CommitEmail = commitAuthor.Email
	vulnerability.CommitMessage = commitAuthor.Message

	return vulnerability
}

func (f *Formatter) getDefaultVulnerabilitySeverity() *horusec.Vulnerability {
	vulnerabilitySeverity := &horusec.Vulnerability{}
	vulnerabilitySeverity.SecurityTool = tools.FlawFinder
	vulnerabilitySeverity.Language = languages.C
	return vulnerabilitySeverity
}

func (f *Formatter) getFilePathFromPackageName(filePath string) string {
	return fileUtil.GetPathIntoFilename(filePath,
		fmt.Sprintf("%s/.horusec/%s/", f.GetConfigProjectPath(), f.GetAnalysisID()))
}
