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

package horuseccsharp

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/csharp"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
)

type Formatter struct {
	formatters.IService
	csharp.Interface
}

func NewFormatter(service formatters.IService) formatters.IFormatter {
	return &Formatter{
		service,
		csharp.NewRules(),
	}
}

func (f *Formatter) StartAnalysis(projectSubPath string) {
	if f.ToolIsToIgnore(tools.HorusecCsharp) {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored+tools.HorusecCsharp.ToString(), logger.DebugLevel)
		return
	}

	f.SetAnalysisError(f.execEngineAndParseResults(projectSubPath), tools.HorusecCsharp, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.HorusecCsharp)
	f.SetToolFinishedAnalysis()
}

func (f *Formatter) execEngineAndParseResults(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.HorusecCsharp)

	findings, err := f.execEngineAnalysis(projectSubPath)
	if err != nil {
		return err
	}

	return f.ParseFindingsToVulnerabilities(findings, tools.HorusecCsharp, languages.CSharp)
}

func (f *Formatter) execEngineAnalysis(projectSubPath string) ([]engine.Finding, error) {
	textUnit, err := f.GetTextUnitByRulesExt(f.GetProjectPathWithWorkdir(projectSubPath))
	if err != nil {
		return nil, err
	}

	allRules := append(f.GetAllRules(), f.GetCustomRulesByTool(tools.HorusecCsharp)...)
	return engine.Run(textUnit, allRules), nil
}
