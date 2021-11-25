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

package formatters

import (
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	engine "github.com/ZupIT/horusec-engine"

	"github.com/ZupIT/horusec/internal/enums/engines"
	"github.com/ZupIT/horusec/internal/helpers/messages"
)

type RuleManager interface {
	GetAllRules() []engine.Rule
	GetTextUnitByRulesExt(src string) ([]engine.Unit, error)
}

// DefaultFormatter is a formatter that can be used with horusec engines implementation
type DefaultFormatter struct {
	svc      IService
	manager  RuleManager
	language languages.Language
}

func NewDefaultFormatter(svc IService, manager RuleManager, language languages.Language) IFormatter {
	return &DefaultFormatter{
		svc:      svc,
		manager:  manager,
		language: language,
	}
}

func (f *DefaultFormatter) StartAnalysis(src string) {
	if f.svc.ToolIsToIgnore(tools.HorusecEngine) {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.HorusecEngine.ToString())
		return
	}
	f.svc.SetAnalysisError(f.execEngineAndParseResults(src), tools.HorusecEngine, "", src)
	f.svc.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.HorusecEngine, f.language)
}

func (f *DefaultFormatter) execEngineAndParseResults(src string) error {
	f.svc.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.HorusecEngine, f.language)

	findings, err := f.execEngineAnalysis(src)
	if err != nil {
		return err
	}
	f.svc.ParseFindingsToVulnerabilities(findings, tools.HorusecEngine, f.language)
	return nil
}

func (f *DefaultFormatter) execEngineAnalysis(src string) ([]engine.Finding, error) {
	textUnit, err := f.manager.GetTextUnitByRulesExt(f.svc.GetProjectPathWithWorkdir(src))
	if err != nil {
		return nil, err
	}

	allRules := append(f.manager.GetAllRules(), f.svc.GetCustomRulesByLanguage(f.language)...)
	return engine.RunMaxUnitsByAnalysis(textUnit, allRules, engines.DefaultMaxUnitsPerAnalysis), nil
}
