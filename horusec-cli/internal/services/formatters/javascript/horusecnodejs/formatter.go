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

package horusecnodejs

import (
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/nodejs/analysis"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
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
	if f.ToolIsToIgnore(tools.HorusecNodejs) {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored+tools.HorusecNodejs.ToString(), logger.DebugLevel)
		return
	}

	f.SetAnalysisError(f.execEngineAndParseResults(projectSubPath), tools.HorusecNodejs, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.HorusecNodejs)
	f.SetToolFinishedAnalysis()
}

func (f *Formatter) execEngineAndParseResults(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.HorusecNodejs)
	findings := f.execEngineAnalysis(projectSubPath)
	return f.ParseFindingsToVulnerabilities(findings, tools.HorusecNodejs, languages.Javascript)
}

func (f *Formatter) execEngineAnalysis(projectSubPath string) []engine.Finding {
	service := analysis.NewAnalysis(f.GetEngineConfig(projectSubPath))
	return service.StartAnalysisCustomRules(nil)
}
