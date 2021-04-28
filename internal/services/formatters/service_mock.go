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
	"github.com/stretchr/testify/mock"

	entitiesAnalysis "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	utilsMock "github.com/ZupIT/horusec-devkit/pkg/utils/mock"
	engine "github.com/ZupIT/horusec-engine"
	commitAuthor "github.com/ZupIT/horusec/internal/entities/commit_author"
	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/entities/monitor"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) LogDebugWithReplace(_ string, _ tools.Tool) {
	_ = m.MethodCalled("LogDebugWithReplace")
}

func (m *Mock) GetAnalysisID() string {
	args := m.MethodCalled("GetAnalysisID")
	return args.Get(0).(string)
}

func (m *Mock) ExecuteContainer(_ *dockerEntities.AnalysisData) (output string, err error) {
	args := m.MethodCalled("ExecuteContainer")
	return args.Get(0).(string), utilsMock.ReturnNilOrError(args, 1)
}

func (m *Mock) GetAnalysisIDErrorMessage(_ tools.Tool, _ string) string {
	args := m.MethodCalled("GetAnalysisIDErrorMessage")
	return args.Get(0).(string)
}

func (m *Mock) GetCommitAuthor(_, _ string) (author commitAuthor.CommitAuthor) {
	args := m.MethodCalled("GetCommitAuthor")
	return args.Get(0).(commitAuthor.CommitAuthor)
}

func (m *Mock) AddWorkDirInCmd(_ string, _ string, _ tools.Tool) string {
	args := m.MethodCalled("AddWorkDirInCmd")
	return args.Get(0).(string)
}

func (m *Mock) GetConfigProjectPath() string {
	args := m.MethodCalled("GetConfigProjectPath")
	return args.Get(0).(string)
}

func (m *Mock) GetAnalysis() *entitiesAnalysis.Analysis {
	args := m.MethodCalled("GetAnalysis")
	return args.Get(0).(*entitiesAnalysis.Analysis)
}

func (m *Mock) SetToolFinishedAnalysis() {
	_ = m.MethodCalled("SetToolFinishedAnalysis")
}

func (m *Mock) SetAnalysisError(_ error, _ tools.Tool, _ string) {
	_ = m.MethodCalled("SetAnalysisError")
}

func (m *Mock) SetMonitor(_ *monitor.Monitor) {
	_ = m.MethodCalled("SetMonitor")
}

func (m *Mock) RemoveSrcFolderFromPath(_ string) string {
	args := m.MethodCalled("RemoveSrcFolderFromPath")
	return args.Get(0).(string)
}

func (m *Mock) GetCodeWithMaxCharacters(_ string, _ int) string {
	args := m.MethodCalled("GetCodeWithMaxCharacters")
	return args.Get(0).(string)
}

func (m *Mock) ToolIsToIgnore(_ tools.Tool) bool {
	args := m.MethodCalled("ToolIsToIgnore")
	return args.Get(0).(bool)
}

func (m *Mock) GetFilepathFromFilename(_ string) string {
	args := m.MethodCalled("GetFilepathFromFilename")
	return args.Get(0).(string)
}

func (m *Mock) GetProjectPathWithWorkdir(_ string) string {
	args := m.MethodCalled("GetProjectPathWithWorkdir")
	return args.Get(0).(string)
}

func (m *Mock) SetCommitAuthor(_ *vulnerability.Vulnerability) *vulnerability.Vulnerability {
	args := m.MethodCalled("SetCommitAuthor")
	return args.Get(0).(*vulnerability.Vulnerability)
}

func (m *Mock) ParseFindingsToVulnerabilities(_ []engine.Finding, _ tools.Tool, _ languages.Language) error {
	args := m.MethodCalled("ParseFindingsToVulnerabilities")
	return utilsMock.ReturnNilOrError(args, 0)
}

func (m *Mock) AddNewVulnerabilityIntoAnalysis(_ *vulnerability.Vulnerability) {
	_ = m.MethodCalled("AddNewVulnerabilityIntoAnalysis")
}

func (m *Mock) GetToolsConfig() toolsconfig.MapToolConfig {
	args := m.MethodCalled("GetToolsConfig")
	return args.Get(0).(toolsconfig.MapToolConfig)
}

func (m *Mock) IsDockerDisabled() bool {
	args := m.MethodCalled("IsDockerDisabled")
	return args.Get(0).(bool)
}

func (m *Mock) GetCustomRulesByLanguage(_ languages.Language) []engine.Rule {
	args := m.MethodCalled("GetCustomRulesByLanguage")
	return args.Get(0).([]engine.Rule)
}

func (m *Mock) GetConfigCMDByFileExtension(_, _, _ string, _ tools.Tool) string {
	args := m.MethodCalled("GetConfigCMDByFileExtension")
	return args.Get(0).(string)
}

func (m *Mock) GetCustomImageByLanguage(_ languages.Language) string {
	args := m.MethodCalled("GetCustomImageByLanguage")
	return args.Get(0).(string)
}
