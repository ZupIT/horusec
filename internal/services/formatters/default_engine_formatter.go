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
	f.svc.SetAnalysisError(f.execEngineAndParseResults(src), tools.HorusecEngine, src)
	f.svc.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.HorusecEngine, f.language)
	f.svc.SetToolFinishedAnalysis()
}

func (f *DefaultFormatter) execEngineAndParseResults(src string) error {
	f.svc.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.HorusecEngine, f.language)

	findings, err := f.execEngineAnalysis(src)
	if err != nil {
		return err
	}

	return f.svc.ParseFindingsToVulnerabilities(findings, tools.HorusecEngine, f.language)
}

func (f *DefaultFormatter) execEngineAnalysis(src string) ([]engine.Finding, error) {
	textUnit, err := f.manager.GetTextUnitByRulesExt(f.svc.GetProjectPathWithWorkdir(src))
	if err != nil {
		return nil, err
	}

	allRules := append(f.manager.GetAllRules(), f.svc.GetCustomRulesByLanguage(f.language)...)
	return engine.RunMaxUnitsByAnalysis(textUnit, allRules, engines.DefaultMaxUnitsPerAnalysis), nil
}
