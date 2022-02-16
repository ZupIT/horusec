// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package testutil

import (
	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	mockutils "github.com/ZupIT/horusec-devkit/pkg/utils/mock"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/stretchr/testify/mock"

	dockerentities "github.com/ZupIT/horusec/internal/entities/docker"
)

type FormatterMock struct {
	mock.Mock
}

func NewFormatterMock() *FormatterMock {
	return new(FormatterMock)
}

func (m *FormatterMock) LogDebugWithReplace(_ string, _ tools.Tool, _ languages.Language) {
	_ = m.MethodCalled("LogDebugWithReplace")
}

func (m *FormatterMock) GetAnalysisID() string {
	args := m.MethodCalled("GetAnalysisID")
	return args.Get(0).(string)
}

func (m *FormatterMock) ExecuteContainer(_ *dockerentities.AnalysisData) (output string, err error) {
	args := m.MethodCalled("ExecuteContainer")
	return args.Get(0).(string), mockutils.ReturnNilOrError(args, 1)
}

func (m *FormatterMock) GetAnalysisIDErrorMessage(_ tools.Tool, _ string) string {
	args := m.MethodCalled("GetAnalysisIDErrorMessage")
	return args.Get(0).(string)
}

func (m *FormatterMock) AddWorkDirInCmd(_, _ string, _ tools.Tool) string {
	args := m.MethodCalled("AddWorkDirInCmd")
	return args.Get(0).(string)
}

func (m *FormatterMock) GetConfigProjectPath() string {
	args := m.MethodCalled("GetConfigProjectPath")
	return args.Get(0).(string)
}

func (m *FormatterMock) SetAnalysisError(_ error, _ tools.Tool, _, _ string) {
	_ = m.MethodCalled("SetAnalysisError")
}

func (m *FormatterMock) RemoveSrcFolderFromPath(_ string) string {
	args := m.MethodCalled("RemoveSrcFolderFromPath")
	return args.Get(0).(string)
}

func (m *FormatterMock) GetCodeWithMaxCharacters(_ string, _ int) string {
	args := m.MethodCalled("GetCodeWithMaxCharacters")
	return args.Get(0).(string)
}

func (m *FormatterMock) ToolIsToIgnore(_ tools.Tool) bool {
	args := m.MethodCalled("ToolIsToIgnore")
	return args.Get(0).(bool)
}

func (m *FormatterMock) GetFilepathFromFilename(_, _ string) (string, error) {
	args := m.MethodCalled("GetFilepathFromFilename")
	return args.Get(0).(string), mockutils.ReturnNilOrError(args, 1)
}

func (m *FormatterMock) SetCommitAuthor(_ *vulnerability.Vulnerability) *vulnerability.Vulnerability {
	args := m.MethodCalled("SetCommitAuthor")
	return args.Get(0).(*vulnerability.Vulnerability)
}

func (m *FormatterMock) ParseFindingsToVulnerabilities(_ []engine.Finding, _ tools.Tool, _ languages.Language) {
	_ = m.MethodCalled("ParseFindingsToVulnerabilities")
}

func (m *FormatterMock) AddNewVulnerabilityIntoAnalysis(_ *vulnerability.Vulnerability) {
	_ = m.MethodCalled("AddNewVulnerabilityIntoAnalysis")
}

func (m *FormatterMock) IsDockerDisabled() bool {
	args := m.MethodCalled("IsDockerDisabled")
	return args.Get(0).(bool)
}

func (m *FormatterMock) GetCustomRulesByLanguage(_ languages.Language) []engine.Rule {
	args := m.MethodCalled("GetCustomRulesByLanguage")
	return args.Get(0).([]engine.Rule)
}

func (m *FormatterMock) GetConfigCMDByFileExtension(_, _, _ string, _ tools.Tool) string {
	args := m.MethodCalled("GetConfigCMDByFileExtension")
	return args.Get(0).(string)
}

func (m *FormatterMock) GetCustomImageByLanguage(_ languages.Language) string {
	args := m.MethodCalled("GetCustomImageByLanguage")
	return args.Get(0).(string)
}

func (m *FormatterMock) IsOwaspDependencyCheckDisable() bool {
	args := m.MethodCalled("IsOwaspDependencyCheckDisable")
	return args.Get(0).(bool)
}

func (m *FormatterMock) IsShellcheckDisable() bool {
	args := m.MethodCalled("IsShellcheckDisable")
	return args.Get(0).(bool)
}

func (m *FormatterMock) IsSemanticEngineEnable() bool {
	args := m.MethodCalled("IsSemanticEngineEnable")
	return args.Get(0).(bool)
}
