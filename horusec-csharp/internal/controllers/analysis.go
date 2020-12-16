package controllers

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/config"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/csharp"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
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
	textUnit, err := a.getTextUnit()
	if err != nil {
		return err
	}

	return engine.RunOutputInJSON([]engine.Unit{textUnit}, a.getAllRules(), a.getOutputFilePath())
}

func (a *Analysis) getTextUnit() (text.TextUnit, error) {
	textUnit, err := text.LoadDirIntoSingleUnit(a.configs.GetProjectPath(), a.getExtensions())
	logger.LogDebugJSON("Text Unit selected is: ", textUnit)
	return textUnit, err
}

func (a *Analysis) getExtensions() []string {
	return []string{".cs", ".vb", ".cshtml", ".csproj", ".xml"}
}

func (a *Analysis) getAllRules() []engine.Rule {
	allRules := a.serviceRules.GetAllRules()
	logger.LogDebugJSON("All rules selected are: ", allRules)
	return allRules
}

func (a *Analysis) getOutputFilePath() string {
	outputFilePath := a.configs.GetOutputFilePath()
	logger.LogDebugWithLevel("Sending units and rules to engine "+
		" and expected response in path: ", logger.DebugLevel, outputFilePath)
	return outputFilePath
}
