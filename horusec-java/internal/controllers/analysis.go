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

package controllers

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec-engine/text"
	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/config"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/java"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
)

type Analysis struct {
	configs      *config.Config
	serviceRules java.Interface
}

func NewAnalysis(configs *config.Config) *Analysis {
	return &Analysis{
		configs:      configs,
		serviceRules: java.NewRules(),
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
	return []string{".java"}
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
