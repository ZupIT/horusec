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
	"github.com/ZupIT/horusec/development-kit/pkg/engines/kotlin/rules"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
)

type Interface interface {
	StartAnalysis() error
}

type Analysis struct {
	configs      *config.Config
	serviceRules rules.Interface
}

func NewAnalysis(configs *config.Config) Interface {
	return &Analysis{
		configs:      configs,
		serviceRules: rules.NewRules(),
	}
}

func (a *Analysis) StartAnalysis() error {
	textUnit, err := text.LoadDirIntoSingleUnit(a.configs.GetProjectPath(), []string{".kt", ".kts"})
	if err != nil {
		return err
	}
	a.logJSON("Text Unit selected is: ", textUnit)

	allRules := a.serviceRules.GetAllRules()
	a.logJSON("All rules selected are: ", allRules)

	outputFilePath := a.configs.GetOutputFilePath()
	logger.LogDebugWithLevel("Sending units and rules to engine "+
		" and expected response in path: ", logger.DebugLevel, outputFilePath)
	return engine.RunOutputInJSON([]engine.Unit{textUnit}, allRules, outputFilePath)
}

func (a *Analysis) logJSON(message string, content interface{}) {
	b, err := json.Marshal(content)
	if err == nil {
		logger.LogTraceWithLevel(message, logger.DebugLevel, string(b))
	}
}
