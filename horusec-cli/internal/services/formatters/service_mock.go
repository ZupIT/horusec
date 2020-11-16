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
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	utilsMock "github.com/ZupIT/horusec/development-kit/pkg/utils/mock"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/stretchr/testify/mock"
)

type Mock struct {
	mock.Mock
}

func (m *Mock) LogDebugWithReplace(msg string, tool tools.Tool) {
	_ = m.MethodCalled("LogDebugWithReplace")
}
func (m *Mock) GetAnalysisID() string {
	args := m.MethodCalled("GetAnalysisID")
	return args.Get(0).(string)
}
func (m *Mock) SetAnalysisError(err error) {
	_ = m.MethodCalled("SetAnalysisError")
}
func (m *Mock) ExecuteContainer(data *dockerEntities.AnalysisData) (output string, err error) {
	args := m.MethodCalled("ExecuteContainer")
	return args.Get(0).(string), utilsMock.ReturnNilOrError(args, 0)
}
func (m *Mock) GetAnalysisIDErrorMessage(tool tools.Tool, output string) string {
	args := m.MethodCalled("GetAnalysisIDErrorMessage")
	return args.Get(0).(string)
}
func (m *Mock) GetCommitAuthor(line, filePath string) (commitAuthor horusec.CommitAuthor) {
	args := m.MethodCalled("GetCommitAuthor")
	return args.Get(0).(horusec.CommitAuthor)
}
func (m *Mock) AddWorkDirInCmd(cmd string, projectSubPath string, tool tools.Tool) string {
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
func (m *Mock) SetLanguageIsFinished() {
	_ = m.MethodCalled("SetLanguageIsFinished")
}
func (m *Mock) LogAnalysisError(err error, tool tools.Tool, projectSubPath string) {
	_ = m.MethodCalled("LogAnalysisError")
}
func (m *Mock) SetMonitor(monitor *horusec.Monitor) {
	_ = m.MethodCalled("SetMonitor")
}
func (m *Mock) RemoveSrcFolderFromPath(filepath string) string {
	args := m.MethodCalled("RemoveSrcFolderFromPath")
	return args.Get(0).(string)
}
func (m *Mock) GetCodeWithMaxCharacters(code string, column int) string {
	args := m.MethodCalled("GetCodeWithMaxCharacters")
	return args.Get(0).(string)
}
func (m *Mock) ToolIsToIgnore(tool tools.Tool) bool {
	args := m.MethodCalled("ToolIsToIgnore")
	return args.Get(0).(bool)
}
