package controllers

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/config"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/csharp"
)

type IAnalysis interface {
	StartAnalysis() error
}

type Analysis struct {
	configs      *config.Config
	serviceRules csharp.Interface
}

func NewAnalysis(configs *config.Config) IAnalysis {
	return &Analysis{
		configs:      configs,
		serviceRules: csharp.NewRules(),
	}
}

func (a *Analysis) StartAnalysis() error {
	textUnit, err := a.serviceRules.GetTextUnitByRulesExt(a.configs.GetProjectPath())
	if err != nil {
		return err
	}

	return engine.RunOutputInJSON(textUnit, a.getAllRules(), a.configs.GetOutputFilePath())
}

func (a *Analysis) getAllRules() []engine.Rule {
	allRules := a.serviceRules.GetAllRules()
	return allRules
}
