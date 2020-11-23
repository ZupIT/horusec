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
	"fmt"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/file"
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	cliConfig "github.com/ZupIT/horusec/horusec-cli/config"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	dockerService "github.com/ZupIT/horusec/horusec-cli/internal/services/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/git"
)

type IService interface {
	LogDebugWithReplace(msg string, tool tools.Tool)
	GetAnalysisID() string
	SetAnalysisError(err error)
	ExecuteContainer(data *dockerEntities.AnalysisData) (output string, err error)
	GetAnalysisIDErrorMessage(tool tools.Tool, output string) string
	GetCommitAuthor(line, filePath string) (commitAuthor horusec.CommitAuthor)
	AddWorkDirInCmd(cmd string, projectSubPath string, tool tools.Tool) string
	GetConfigProjectPath() string
	GetAnalysis() *horusec.Analysis
	SetLanguageIsFinished()
	LogAnalysisError(err error, tool tools.Tool, projectSubPath string)
	SetMonitor(monitor *horusec.Monitor)
	RemoveSrcFolderFromPath(filepath string) string
	GetCodeWithMaxCharacters(code string, column int) string
	ToolIsToIgnore(tool tools.Tool) bool
}

type Service struct {
	analysis   *horusec.Analysis
	docker     dockerService.Interface
	gitService git.IService
	monitor    *horusec.Monitor
	config     *cliConfig.Config
}

func NewFormatterService(analysis *horusec.Analysis, docker dockerService.Interface, config *cliConfig.Config,
	monitor *horusec.Monitor) IService {
	return &Service{
		analysis:   analysis,
		docker:     docker,
		gitService: git.NewGitService(config),
		monitor:    monitor,
		config:     config,
	}
}

func (s *Service) ExecuteContainer(data *dockerEntities.AnalysisData) (output string, err error) {
	return s.docker.CreateLanguageAnalysisContainer(data)
}

func (s *Service) GetAnalysisIDErrorMessage(tool tools.Tool, output string) string {
	msg := strings.ReplaceAll(messages.MsgErrorRunToolInDocker, "{{0}}", tool.ToString())
	msg = strings.ReplaceAll(msg, "{{1}}", s.GetAnalysisID())
	msg = strings.ReplaceAll(msg, "{{2}}", output)
	return msg
}

func (s *Service) GetCommitAuthor(line, filePath string) (commitAuthor horusec.CommitAuthor) {
	return s.gitService.GetCommitAuthor(line, filePath)
}

func (s *Service) GetConfigProjectPath() string {
	return file.ReplacePathSeparator(fmt.Sprintf("%s/%s/%s", s.config.ProjectPath, ".horusec", s.analysis.ID.String()))
}

func (s *Service) AddWorkDirInCmd(cmd, projectSubPath string, tool tools.Tool) string {
	if projectSubPath != "" {
		logger.LogDebugWithLevel(messages.MsgDebugShowWorkdir, logger.DebugLevel, tool.ToString(), projectSubPath)
		return strings.ReplaceAll(cmd, "{{WORK_DIR}}", fmt.Sprintf("cd %s", projectSubPath))
	}

	return strings.ReplaceAll(cmd, "{{WORK_DIR}}", "")
}

func (s *Service) LogDebugWithReplace(msg string, tool tools.Tool) {
	logger.LogDebugWithLevel(strings.ReplaceAll(msg, "{{0}}", tool.ToString()),
		logger.DebugLevel, s.analysis.GetIDString())
}

func (s *Service) GetAnalysisID() string {
	return s.analysis.GetIDString()
}

func (s *Service) GetAnalysis() *horusec.Analysis {
	return s.analysis
}

func (s *Service) SetAnalysisError(err error) {
	s.analysis.SetAnalysisError(err)
}

func (s *Service) LogAnalysisError(err error, tool tools.Tool, projectSubPath string) {
	if err != nil {
		msg := s.GetAnalysisIDErrorMessage(tool, "")
		if projectSubPath != "" {
			msg += " | ProjectSubPath -> " + projectSubPath
		}

		msg = strings.ReplaceAll(msg, "| output -> {{2}}", "")
		logger.LogDebugWithLevel(fmt.Sprintf("%s - %s", msg, err), logger.ErrorLevel)
	}
}

func (s *Service) SetLanguageIsFinished() {
	s.monitor.RemoveProcess(1)
}

func (s *Service) SetMonitor(monitor *horusec.Monitor) {
	s.monitor = monitor
}

func (s *Service) RemoveSrcFolderFromPath(filepath string) string {
	if filepath == "" || len(filepath) <= 4 || !strings.Contains(filepath[:4], "src") {
		return filepath
	}

	return filepath[5:]
}

func (s *Service) GetCodeWithMaxCharacters(code string, column int) string {
	if column < 0 {
		column = 0
	}

	if len(code) > 100 {
		return s.getAHundredCharacters(code, column)
	}

	return code
}

func (s *Service) ToolIsToIgnore(tool tools.Tool) bool {
	allTools := strings.Split(s.config.GetToolsToIgnore(), ",")

	for _, toolToIgnore := range allTools {
		if strings.EqualFold(strings.TrimSpace(toolToIgnore), tool.ToString()) {
			s.SetLanguageIsFinished()
			return true
		}
	}

	return false
}

func (s *Service) getAHundredCharacters(code string, column int) string {
	if len(code) < column {
		return code[:100]
	}

	codeFromColumn := code[column:]
	if len(codeFromColumn) > 100 {
		return codeFromColumn[:100]
	}

	return codeFromColumn
}
