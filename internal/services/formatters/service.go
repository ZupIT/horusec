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
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	commitauthor "github.com/ZupIT/horusec/internal/entities/commit_author"
	"github.com/ZupIT/horusec/internal/utils/file"
	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/config"
	dockerentity "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	custonrules "github.com/ZupIT/horusec/internal/services/custom_rules"
	"github.com/ZupIT/horusec/internal/services/docker"
	"github.com/ZupIT/horusec/internal/services/git"
)

// CustomRules is the interface that load custom rules to a given language
type CustomRules interface {
	Load(languages.Language) []engine.Rule
}

// Git is the interface that handle Git operations
type Git interface {
	CommitAuthor(line string, file string) commitauthor.CommitAuthor
}

type Service struct {
	mutex       *sync.Mutex
	analysis    *analysis.Analysis
	docker      docker.Docker
	git         Git
	config      *config.Config
	customRules CustomRules
}

func NewFormatterService(analysiss *analysis.Analysis, dockerSvc docker.Docker, cfg *config.Config) IService {
	return &Service{
		mutex:       new(sync.Mutex),
		analysis:    analysiss,
		docker:      dockerSvc,
		git:         git.New(cfg),
		config:      cfg,
		customRules: custonrules.NewCustomRulesService(cfg),
	}
}

func (s *Service) ExecuteContainer(data *dockerentity.AnalysisData) (output string, err error) {
	return s.docker.CreateLanguageAnalysisContainer(data)
}

func (s *Service) GetAnalysisIDErrorMessage(tool tools.Tool, output string) string {
	msg := strings.ReplaceAll(messages.MsgErrorRunToolInDocker, "{{0}}", tool.ToString())
	msg = strings.ReplaceAll(msg, "{{1}}", s.GetAnalysisID())
	msg = strings.ReplaceAll(msg, "{{2}}", output)
	return msg
}

func (s *Service) GetCommitAuthor(line, filePath string) commitauthor.CommitAuthor {
	return s.git.CommitAuthor(line, filePath)
}

func (s *Service) GetConfigProjectPath() string {
	return file.ReplacePathSeparator(
		fmt.Sprintf(
			"%s/%s/%s",
			s.config.ProjectPath,
			".horusec",
			s.analysis.ID.String(),
		),
	)
}

func (s *Service) GetToolsConfig() toolsconfig.MapToolConfig {
	return s.config.ToolsConfig
}

func (s *Service) AddWorkDirInCmd(cmd, projectSubPath string, tool tools.Tool) string {
	if projectSubPath != "" {
		logger.LogDebugWithLevel(messages.MsgDebugShowWorkdir, tool.ToString(), projectSubPath)
		return strings.ReplaceAll(cmd, "{{WORK_DIR}}", fmt.Sprintf("cd %s", projectSubPath))
	}

	return strings.ReplaceAll(cmd, "{{WORK_DIR}}", "")
}

func (s *Service) LogDebugWithReplace(msg string, tool tools.Tool, lang languages.Language) {
	newMsg := strings.ReplaceAll(msg, "{{0}}", tool.ToString())
	newMsg = strings.ReplaceAll(newMsg, "{{1}}", lang.ToString())
	logger.LogDebugWithLevel(newMsg, s.analysis.GetIDString())
}

func (s *Service) GetAnalysisID() string {
	return s.analysis.GetIDString()
}

func (s *Service) GetAnalysis() *analysis.Analysis {
	return s.analysis
}

func (s *Service) SetAnalysisError(err error, tool tools.Tool, projectSubPath string) {
	if err != nil {
		s.mutex.Lock()
		defer s.mutex.Unlock()
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
	if tool, exists := s.config.ToolsConfig[tool]; exists {
		return tool.IsToIgnore
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

func (s *Service) GetFilepathFromFilename(filename, projectSubPath string) string {
	basePath := file.ReplacePathSeparator(path.Join(s.GetConfigProjectPath(), projectSubPath))
	filepath := file.GetPathIntoFilename(filename, basePath)
	if filepath != "" {
		return path.Join(projectSubPath, filepath[1:])
	}

	return path.Join(projectSubPath, filepath)
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
		analysis.AnalysisVulnerabilities{
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
	return s.config.DisableDocker
}

func (s *Service) GetCustomRulesByLanguage(lang languages.Language) []engine.Rule {
	return s.customRules.Load(lang)
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
	return s.config.CustomImages[language.GetCustomImagesKeyByLanguage()]
}

func (s *Service) IsOwaspDependencyCheckDisable() bool {
	return !s.config.EnableOwaspDependencyCheck
}

func (s *Service) IsShellcheckDisable() bool {
	return !s.config.EnableShellCheck
}
