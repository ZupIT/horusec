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
	textUnit, err := a.serviceRules.GetTextUnitByRulesExt(a.configs.GetProjectPath())
	if err != nil {
		return err
	}

	return engine.RunOutputInJSON(textUnit, a.getAllRules(), a.configs.GetOutputFilePath())
}

func (a *Analysis) getAllRules() []engine.Rule {
	allRules := a.serviceRules.GetAllRules()
	logger.LogDebugJSON("All rules selected are: ", allRules)
	return allRules
}
