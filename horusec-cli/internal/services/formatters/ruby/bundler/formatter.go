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
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
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

	return f.parseOutput(output)
}

func (f *Formatter) getDockerConfig(projectSubPath string) *dockerEntities.AnalysisData {
	analysisData := &dockerEntities.AnalysisData{
		CMD:      f.AddWorkDirInCmd(ImageCmd, projectSubPath, tools.BundlerAudit),
		Language: languages.Ruby,
	}

	return analysisData.SetFullImagePath(
		f.GetToolsConfig()[tools.BundlerAudit].ImagePath, ImageRepository, ImageName, ImageTag)
}

func (f *Formatter) parseOutput(output string) error {
	//if containerOutput == "" {
	//	return nil
	//}
	//

	return nil
}

//
//func (f *Formatter) setVulnerabilityData(output *entities.Warning) *horusec.Vulnerability {
//	data := f.getDefaultVulnerabilitySeverity()
//	data.Severity = output.GetSeverity()
//	data.Confidence = output.GetSeverity().ToString()
//	data.Details = output.GetDetails()
//	data.Line = output.GetLine()
//	data.File = output.File
//	data.Code = f.GetCodeWithMaxCharacters(output.Code, 0)
//	data = hash.Bind(data)
//	return f.SetCommitAuthor(data)
//}
//
//func (f *Formatter) getDefaultVulnerabilitySeverity() *horusec.Vulnerability {
//	vulnerabilitySeverity := &horusec.Vulnerability{}
//	vulnerabilitySeverity.SecurityTool = tools.BundlerAudit
//	vulnerabilitySeverity.Language = languages.Ruby
//	return vulnerabilitySeverity
//}
