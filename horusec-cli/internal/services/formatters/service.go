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
	"os"
	"strconv"
	"strings"

	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/tools"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/file"
	fileUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/file"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	hash "github.com/ZupIT/horusec/development-kit/pkg/utils/vuln_hash"
	cliConfig "github.com/ZupIT/horusec/horusec-cli/config"
	dockerEntities "github.com/ZupIT/horusec/horusec-cli/internal/entities/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	customRules "github.com/ZupIT/horusec/horusec-cli/internal/services/custom_rules"
	dockerService "github.com/ZupIT/horusec/horusec-cli/internal/services/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/git"
)

type Service struct {
	analysis           *horusec.Analysis
	docker             dockerService.Interface
	gitService         git.IService
	monitor            *horusec.Monitor
	config             cliConfig.IConfig
	customRulesService customRules.IService
}

func NewFormatterService(analysis *horusec.Analysis, docker dockerService.Interface, config cliConfig.IConfig,
	monitor *horusec.Monitor) IService {
	return &Service{
		analysis:           analysis,
		docker:             docker,
		gitService:         git.NewGitService(config),
		monitor:            monitor,
		config:             config,
		customRulesService: customRules.NewCustomRulesService(config),
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
	return file.ReplacePathSeparator(
		fmt.Sprintf(
			"%s/%s/%s",
			s.config.GetProjectPath(),
			".horusec",
			s.analysis.ID.String(),
		),
	)
}

func (s *Service) GetToolsConfig() toolsconfig.MapToolConfig {
	return s.config.GetToolsConfig()
}

func (s *Service) AddWorkDirInCmd(cmd, projectSubPath string, tool tools.Tool) string {
	if projectSubPath != "" {
		logger.LogDebugWithLevel(messages.MsgDebugShowWorkdir, tool.ToString(), projectSubPath)
		return strings.ReplaceAll(cmd, "{{WORK_DIR}}", fmt.Sprintf("cd %s", projectSubPath))
	}

	return strings.ReplaceAll(cmd, "{{WORK_DIR}}", "")
}

func (s *Service) LogDebugWithReplace(msg string, tool tools.Tool) {
	logger.LogDebugWithLevel(strings.ReplaceAll(msg, "{{0}}", tool.ToString()),
		s.analysis.GetIDString())
}

func (s *Service) GetAnalysisID() string {
	return s.analysis.GetIDString()
}

func (s *Service) GetAnalysis() *horusec.Analysis {
	return s.analysis
}

func (s *Service) SetAnalysisError(err error, tool tools.Tool, projectSubPath string) {
	if err != nil {
		s.analysis.SetAnalysisError(err)
		msg := s.GetAnalysisIDErrorMessage(tool, "")
		if projectSubPath != "" {
			msg += " | ProjectSubPath -> " + projectSubPath
		}

		msg = strings.ReplaceAll(msg, "| output -> {{2}}", "")
		logger.LogDebugWithLevel(fmt.Sprintf("%s - %s", msg, err))
	}
}

func (s *Service) SetToolFinishedAnalysis() {
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
	// TODO method GetToolsToIgnore will deprecated in future
	for _, toolToIgnore := range s.config.GetToolsToIgnore() {
		if strings.EqualFold(toolToIgnore, tool.ToString()) {
			s.SetToolFinishedAnalysis()
			return true
		}
	}
	if s.config.GetToolsConfig()[tool].IsToIgnore {
		s.SetToolFinishedAnalysis()
		return true
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

func (s *Service) GetFilepathFromFilename(filename string) string {
	filepath := file.GetPathIntoFilename(filename, s.GetConfigProjectPath())
	if filepath != "" {
		return filepath[1:]
	}

	return filepath
}

func (s *Service) GetProjectPathWithWorkdir(projectSubPath string) string {
	if projectSubPath != "" && projectSubPath[0:1] == string(os.PathSeparator) {
		return fmt.Sprintf("%s%s", s.GetConfigProjectPath(), projectSubPath)
	}

	return fmt.Sprintf("%s%s%s", s.GetConfigProjectPath(), string(os.PathSeparator), projectSubPath)
}

func (s *Service) SetCommitAuthor(vulnerability *horusec.Vulnerability) *horusec.Vulnerability {
	commitAuthor := s.GetCommitAuthor(vulnerability.Line, vulnerability.File)

	vulnerability.CommitAuthor = commitAuthor.Author
	vulnerability.CommitEmail = commitAuthor.Email
	vulnerability.CommitHash = commitAuthor.CommitHash
	vulnerability.CommitMessage = commitAuthor.Message
	vulnerability.CommitDate = commitAuthor.Date

	return vulnerability
}

func (s *Service) ParseFindingsToVulnerabilities(findings []engine.Finding, tool tools.Tool,
	language languages.Language) error {
	for index := range findings {
		s.setVulnerabilityDataByFindings(findings, index, tool, language)
	}

	return nil
}

func (s *Service) setVulnerabilityDataByFindings(findings []engine.Finding, index int, tool tools.Tool,
	language languages.Language) {
	vulnerability := s.setVulnerabilityDataByFindingIndex(findings, index, tool, language)
	vulnerability = s.SetCommitAuthor(vulnerability)
	vulnerability = hash.Bind(vulnerability)
	s.AddNewVulnerabilityIntoAnalysis(vulnerability)
}

func (s *Service) AddNewVulnerabilityIntoAnalysis(vulnerability *horusec.Vulnerability) {
	s.GetAnalysis().AnalysisVulnerabilities = append(s.GetAnalysis().AnalysisVulnerabilities,
		horusec.AnalysisVulnerabilities{
			Vulnerability: *vulnerability,
		})
}

func (s *Service) setVulnerabilityDataByFindingIndex(findings []engine.Finding, index int, tool tools.Tool,
	language languages.Language) *horusec.Vulnerability {
	return &horusec.Vulnerability{
		Line:         strconv.Itoa(findings[index].SourceLocation.Line),
		Column:       strconv.Itoa(findings[index].SourceLocation.Column),
		Confidence:   findings[index].Confidence,
		File:         s.removeHorusecFolder(findings[index].SourceLocation.Filename),
		Code:         s.GetCodeWithMaxCharacters(findings[index].CodeSample, findings[index].SourceLocation.Column),
		Details:      findings[index].Name + "\n" + findings[index].Description,
		SecurityTool: tool,
		Language:     language,
		Severity:     severity.ParseStringToSeverity(findings[index].Severity),
	}
}

func (s *Service) removeHorusecFolder(filepath string) string {
	toRemove := fmt.Sprintf("%s/", s.GetConfigProjectPath())
	return strings.ReplaceAll(filepath, toRemove, "")
}

func (s *Service) IsDockerDisabled() bool {
	isDisabled := s.config.GetDisableDocker()
	if isDisabled {
		s.SetToolFinishedAnalysis()
	}

	return isDisabled
}

func (s *Service) GetCustomRulesByTool(tool tools.Tool) []engine.Rule {
	return s.customRulesService.GetCustomRulesByTool(tool)
}

func (s *Service) GetConfigCMDByFileExtension(projectSubPath, imageCmd, ext string, tool tools.Tool) string {
	projectPath := s.GetConfigProjectPath()

	newProjectSubPath := fileUtil.GetSubPathByExtension(projectPath, projectSubPath, ext)
	if newProjectSubPath != "" {
		return s.AddWorkDirInCmd(imageCmd, newProjectSubPath, tool)
	}

	return s.AddWorkDirInCmd(imageCmd, projectSubPath, tool)
}
