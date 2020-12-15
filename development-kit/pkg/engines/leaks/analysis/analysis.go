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

package analysis

import (
	"encoding/json"

	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/config"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/leaks/rules"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
)

type Analysis struct {
	configs      *config.Config
	serviceRules rules.Interface
}

func NewAnalysis(configs *config.Config) *Analysis {
	return &Analysis{
		configs:      configs,
		serviceRules: rules.NewRules(),
	}
}

func (a *Analysis) StartAnalysis() error {
	textUnits, err := text.LoadDirIntoMultiUnit(a.configs.GetProjectPath(), 5, []string{"**"})
	if err != nil {
		return err
	}
	units := a.parseTextUnitsToUnits(textUnits)
	a.logJSON("Texts Units selected are: ", textUnits)

	allRules := a.serviceRules.GetAllRules()
	a.logJSON("All rules selected are: ", allRules)

	outputFilePath := a.configs.GetOutputFilePath()
	logger.LogDebugWithLevel("Sending units and rules to engine "+
		" and expected response in path: ", logger.DebugLevel, outputFilePath)
	return engine.RunOutputInJSON(units, allRules, outputFilePath)
}

func (a *Analysis) StartAnalysisCustomRules(customRules []engine.Rule) []engine.Finding {
	textUnits, err := text.LoadDirIntoMultiUnit(a.configs.GetProjectPath(), 5, []string{"**"})
	if err != nil {
		logger.LogError("failed to get text unity", err)
		return nil
	}
	units := a.parseTextUnitsToUnits(textUnits)
	a.logJSON("Texts Units selected are: ", textUnits)

	allRules := append(a.serviceRules.GetAllRules(), customRules...)
	a.logJSON("All rules selected are: ", allRules)

	outputFilePath := a.configs.GetOutputFilePath()
	logger.LogDebugWithLevel("Sending units and rules to engine "+
		" and expected response in path: ", logger.DebugLevel, outputFilePath)
	return engine.Run(units, allRules)
}

func (a *Analysis) logJSON(message string, content interface{}) {
	b, err := json.Marshal(content)
	if err == nil {
		logger.LogTraceWithLevel(message, logger.DebugLevel, string(b))
	}
}

func (a *Analysis) parseTextUnitsToUnits(textUnits []text.TextUnit) (units []engine.Unit) {
	for index := range textUnits {
		units = append(units, textUnits[index])
	}
	return units
}
