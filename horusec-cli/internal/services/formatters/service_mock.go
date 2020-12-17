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
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	utilsMock "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/stretchr/testify/mock"
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

func (m *Mock) GetCommitAuthor(_, _ string) (commitAuthor horusec.CommitAuthor) {
	args := m.MethodCalled("GetCommitAuthor")
	return args.Get(0).(horusec.CommitAuthor)
}

func (m *Mock) AddWorkDirInCmd(_ string, _ string, _ tools.Tool) string {
	args := m.MethodCalled("AddWorkDirInCmd")
	return args.Get(0).(string)
}

func (m *Mock) GetConfigProjectPath() string {
	args := m.MethodCalled("GetConfigProjectPath")
	return args.Get(0).(string)
}

func (m *Mock) GetAnalysis() *horusec.Analysis {
	args := m.MethodCalled("GetAnalysis")
	return args.Get(0).(*horusec.Analysis)
}

func (m *Mock) SetToolFinishedAnalysis() {
	_ = m.MethodCalled("SetToolFinishedAnalysis")
}

func (m *Mock) SetAnalysisError(_ error, _ tools.Tool, _ string) {
	_ = m.MethodCalled("SetAnalysisError")
}

func (m *Mock) SetMonitor(_ *horusec.Monitor) {
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

func (m *Mock) SetCommitAuthor(_ *horusec.Vulnerability) *horusec.Vulnerability {
	args := m.MethodCalled("SetCommitAuthor")
	return args.Get(0).(*horusec.Vulnerability)
}

func (m *Mock) ParseFindingsToVulnerabilities(_ []engine.Finding, _ tools.Tool, _ languages.Language) error {
	args := m.MethodCalled("ParseFindingsToVulnerabilities")
	return utilsMock.ReturnNilOrError(args, 0)
}

func (m *Mock) AddNewVulnerabilityIntoAnalysis(_ *horusec.Vulnerability) {
	_ = m.MethodCalled("AddNewVulnerabilityIntoAnalysis")
}
