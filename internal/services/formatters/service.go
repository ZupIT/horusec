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

	entitiesAnalysis "github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	commitAuthor "github.com/ZupIT/horusec/internal/entities/commit_author"
	"github.com/ZupIT/horusec/internal/entities/monitor"
	"github.com/ZupIT/horusec/internal/utils/file"
	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	engine "github.com/ZupIT/horusec-engine"
	cliConfig "github.com/ZupIT/horusec/config"
	dockerEntities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	customRules "github.com/ZupIT/horusec/internal/services/custom_rules"
	dockerService "github.com/ZupIT/horusec/internal/services/docker"
	"github.com/ZupIT/horusec/internal/services/git"
)

type Service struct {
	analysis           *entitiesAnalysis.Analysis
	docker             dockerService.Interface
	gitService         git.IService
	monitor            *monitor.Monitor
	config             cliConfig.IConfig
	customRulesService customRules.IService
}

func NewFormatterService(analysis *entitiesAnalysis.Analysis, docker dockerService.Interface, config cliConfig.IConfig,
	monitorEntity *monitor.Monitor) IService {
	return &Service{
		analysis:           analysis,
		docker:             docker,
		gitService:         git.NewGitService(config),
		monitor:            monitorEntity,
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

func (s *Service) GetCommitAuthor(line, filePath string) commitAuthor.CommitAuthor {
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

func (s *Service) GetAnalysis() *entitiesAnalysis.Analysis {
	return s.analysis
}

func (s *Service) SetAnalysisError(err error, tool tools.Tool, projectSubPath string) {
	if err != nil {
		s.addAnalysisError(err)
		msg := s.GetAnalysisIDErrorMessage(tool, "")
		if projectSubPath != "" {
			msg += " | ProjectSubPath -> " + projectSubPath
		}

		msg = strings.ReplaceAll(msg, "| output -> {{2}}", "")
		logger.LogDebugWithLevel(fmt.Sprintf("%s - %s", msg, err))
	}
}

func (s *Service) addAnalysisError(err error) {
	if err != nil {
		toAppend := ""
		if len(s.analysis.Errors) > 0 {
			s.analysis.Errors += "; " + err.Error()
			return
		}
		s.analysis.Errors += toAppend + err.Error()
	}
}

func (s *Service) SetToolFinishedAnalysis() {
	s.monitor.RemoveProcess(1)
}

func (s *Service) SetMonitor(monitorToSet *monitor.Monitor) {
	s.monitor = monitorToSet
}

func (s *Service) RemoveSrcFolderFromPath(filepath string) string {
	if filepath == "" || len(filepath) <= 4 || !strings.Contains(filepath[:4], "src") {
		return filepath
	}

	return filepath[5:]
}

func (s *Service) GetCodeWithMaxCharacters(code string, column int) string {
	const MaxCharacters = 100
	if column < 0 {
		column = 0
	}

	if len(code) > MaxCharacters {
		return s.getAHundredCharacters(code, column)
	}

	return code
}

func (s *Service) ToolIsToIgnore(tool tools.Tool) bool {
	if s.config.GetToolsConfig()[tool].IsToIgnore {
		s.SetToolFinishedAnalysis()
		return true
	}
	return false
}

func (s *Service) getAHundredCharacters(code string, column int) string {
	const MaxCharacters = 100
	if len(code) < column {
		return code[:MaxCharacters]
	}

	codeFromColumn := code[column:]
	if len(codeFromColumn) > MaxCharacters {
		return codeFromColumn[:MaxCharacters]
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

func (s *Service) SetCommitAuthor(vuln *vulnerability.Vulnerability) *vulnerability.Vulnerability {
	author := s.GetCommitAuthor(vuln.Line, vuln.File)

	vuln.CommitAuthor = author.Author
	vuln.CommitEmail = author.Email
	vuln.CommitHash = author.CommitHash
	vuln.CommitMessage = author.Message
	vuln.CommitDate = author.Date

	return vuln
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
	vuln := s.setVulnerabilityDataByFindingIndex(findings, index, tool, language)
	vuln = s.SetCommitAuthor(vuln)
	vuln = vulnhash.Bind(vuln)
	s.AddNewVulnerabilityIntoAnalysis(vuln)
}

func (s *Service) AddNewVulnerabilityIntoAnalysis(vuln *vulnerability.Vulnerability) {
	s.GetAnalysis().AnalysisVulnerabilities = append(s.GetAnalysis().AnalysisVulnerabilities,
		entitiesAnalysis.AnalysisVulnerabilities{
			Vulnerability: *vuln,
		})
}

func (s *Service) setVulnerabilityDataByFindingIndex(findings []engine.Finding, index int, tool tools.Tool,
	language languages.Language) *vulnerability.Vulnerability {
	return &vulnerability.Vulnerability{
		Line:         strconv.Itoa(findings[index].SourceLocation.Line),
		Column:       strconv.Itoa(findings[index].SourceLocation.Column),
		Confidence:   confidence.Confidence(findings[index].Confidence),
		File:         s.removeHorusecFolder(findings[index].SourceLocation.Filename),
		Code:         s.GetCodeWithMaxCharacters(findings[index].CodeSample, findings[index].SourceLocation.Column),
		Details:      findings[index].Name + "\n" + findings[index].Description,
		SecurityTool: tool,
		Language:     language,
		Severity:     severities.GetSeverityByString(findings[index].Severity),
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

func (s *Service) GetCustomRulesByLanguage(lang languages.Language) []engine.Rule {
	return s.customRulesService.GetCustomRulesByLanguage(lang)
}

func (s *Service) GetConfigCMDByFileExtension(projectSubPath, imageCmd, ext string, tool tools.Tool) string {
	projectPath := s.GetConfigProjectPath()

	newProjectSubPath := file.GetSubPathByExtension(projectPath, projectSubPath, ext)
	if newProjectSubPath != "" {
		return s.AddWorkDirInCmd(imageCmd, newProjectSubPath, tool)
	}

	return s.AddWorkDirInCmd(imageCmd, projectSubPath, tool)
}

func (s *Service) GetCustomImageByLanguage(language languages.Language) string {
	return s.config.GetCustomImages()[language.GetCustomImagesKeyByLanguage()]
}
