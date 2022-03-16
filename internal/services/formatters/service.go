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
	"bytes"
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	engine "github.com/ZupIT/horusec-engine"

	"github.com/ZupIT/horusec/config"
	dockerentity "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	customrules "github.com/ZupIT/horusec/internal/services/custom_rules"
	"github.com/ZupIT/horusec/internal/services/docker"
	"github.com/ZupIT/horusec/internal/services/git"
	"github.com/ZupIT/horusec/internal/utils/file"
	vulnhash "github.com/ZupIT/horusec/internal/utils/vuln_hash"
)

// MaxCharacters is the maximum length of code that a vulnerability can have.
const MaxCharacters = 100

// CustomRules is the interface that load custom rules to a given language
type CustomRules interface {
	Load(languages.Language) []engine.Rule
}

// Git is the interface that handle Git operations
type Git interface {
	CommitAuthor(line string, file string) git.CommitAuthor
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
		customRules: customrules.NewCustomRulesService(cfg),
	}
}

func (s *Service) ExecuteContainer(data *dockerentity.AnalysisData) (output string, err error) {
	return s.docker.CreateLanguageAnalysisContainer(data)
}

func (s *Service) GetAnalysisIDErrorMessage(tool tools.Tool, output string) string {
	return fmt.Sprintf(messages.MsgErrorRunToolInDocker, tool, s.GetAnalysisID(), output)
}

func (s *Service) GetConfigProjectPath() string {
	return filepath.Join(s.config.ProjectPath, ".horusec", s.analysis.ID.String())
}

func (s *Service) AddWorkDirInCmd(cmd, projectSubPath string, tool tools.Tool) string {
	if projectSubPath != "" {
		// Since the command will run inside a Docker container we need
		// to convert any Windows slash (\) to Unix slash (/).
		projectSubPath = filepath.ToSlash(projectSubPath)
		logger.LogDebugWithLevel(fmt.Sprintf(messages.MsgDebugShowWorkdir, projectSubPath, tool.ToString()))
		return strings.ReplaceAll(cmd, "{{WORK_DIR}}", fmt.Sprintf("cd %s", projectSubPath))
	}

	return strings.ReplaceAll(cmd, "{{WORK_DIR}}", "")
}

func (s *Service) LogDebugWithReplace(msg string, tool tools.Tool, lang languages.Language) {
	logger.LogDebugWithLevel(fmt.Sprintf(msg, tool, lang, s.analysis.GetIDString()))
}

func (s *Service) GetAnalysisID() string {
	return s.analysis.GetIDString()
}

func (s *Service) SetAnalysisError(err error, tool tools.Tool, output, projectSubPath string) {
	if err != nil {
		s.mutex.Lock()
		defer s.mutex.Unlock()
		s.addAnalysisError(tool, err)
		msg := s.GetAnalysisIDErrorMessage(tool, output)
		if projectSubPath != "" {
			msg += " | ProjectSubPath -> " + projectSubPath
		}

		msg = strings.ReplaceAll(msg, "| output -> {{2}}", "")
		logger.LogDebugWithLevel(fmt.Sprintf("%s - %s", msg, err))
	}
}

func (s *Service) addAnalysisError(tool tools.Tool, err error) {
	if err != nil {
		buf := bytes.NewBufferString("")
		if len(s.analysis.Errors) > 0 {
			fmt.Fprintf(buf, ";")
		}
		fmt.Fprintf(buf, "{HORUSEC_CLI} Error while running tool %s: %v", tool, err)
		s.analysis.Errors += buf.String()
	}
}

func (s *Service) RemoveSrcFolderFromPath(path string) string {
	if path == "" || len(path) <= 4 || !strings.Contains(path[:4], "src") {
		return path
	}

	path = strings.Replace(filepath.ToSlash(path), "/src/", "", 1)

	if runtime.GOOS == "windows" {
		return filepath.FromSlash(path)
	}

	return path
}

func (s *Service) GetCodeWithMaxCharacters(code string, column int) string {
	if column < 0 {
		column = 0
	}

	if len(code) > MaxCharacters {
		return s.truncatedCode(code, column)
	}

	return code
}

func (s *Service) ToolIsToIgnore(tool tools.Tool) bool {
	if tool, exists := s.config.ToolsConfig[tool]; exists {
		return tool.IsToIgnore
	}
	return false
}

func (s *Service) truncatedCode(code string, column int) string {
	if len(code) < column {
		return code[:MaxCharacters]
	}

	codeFromColumn := code[column:]
	if len(codeFromColumn) > MaxCharacters {
		return codeFromColumn[:MaxCharacters]
	}

	return codeFromColumn
}

func (s *Service) GetFilepathFromFilename(filename, projectSubPath string) (string, error) {
	basePath := filepath.Join(s.GetConfigProjectPath(), projectSubPath)
	filepathWithFileName, err := file.GetPathFromFilename(filename, basePath)
	if err != nil {
		return "", err
	}

	return filepath.Join(projectSubPath, filepathWithFileName), err
}

func (s *Service) SetCommitAuthor(vuln *vulnerability.Vulnerability) *vulnerability.Vulnerability {
	author := s.git.CommitAuthor(vuln.Line, vuln.File)

	vuln.CommitAuthor = author.Author
	vuln.CommitEmail = author.Email
	vuln.CommitHash = author.CommitHash
	vuln.CommitMessage = author.Message
	vuln.CommitDate = author.Date

	return vuln
}

func (s *Service) ParseFindingsToVulnerabilities(findings []engine.Finding, tool tools.Tool,
	language languages.Language,
) {
	for index := range findings {
		vuln := s.newVulnerabilityFromFinding(&findings[index], tool, language)
		vuln = s.SetCommitAuthor(vuln)
		vuln = vulnhash.Bind(vuln)
		s.AddNewVulnerabilityIntoAnalysis(vuln)
	}
}

func (s *Service) AddNewVulnerabilityIntoAnalysis(vuln *vulnerability.Vulnerability) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.analysis.AnalysisVulnerabilities = append(s.analysis.AnalysisVulnerabilities,
		analysis.AnalysisVulnerabilities{
			Vulnerability: *vuln,
		})
}

func (s *Service) newVulnerabilityFromFinding(finding *engine.Finding, tool tools.Tool,
	language languages.Language,
) *vulnerability.Vulnerability {
	return &vulnerability.Vulnerability{
		RuleID:       finding.ID,
		Line:         strconv.Itoa(finding.SourceLocation.Line),
		Column:       strconv.Itoa(finding.SourceLocation.Column),
		Confidence:   confidence.Confidence(finding.Confidence),
		File:         s.removeHorusecFolder(finding.SourceLocation.Filename),
		Code:         s.GetCodeWithMaxCharacters(finding.CodeSample, finding.SourceLocation.Column),
		Details:      fmt.Sprintf("%s\n%s", finding.Name, finding.Description),
		SecurityTool: tool,
		Language:     language,
		Severity:     severities.GetSeverityByString(finding.Severity),
	}
}

func (s *Service) removeHorusecFolder(path string) string {
	rel, err := filepath.Rel(s.GetConfigProjectPath(), path)
	if err != nil {
		logger.LogError(messages.MsgErrorGetRelativePathFromFile, err, map[string]interface{}{
			"basepath": s.GetConfigProjectPath(),
			"path":     path,
		})
		// Since all files will be analyzed from GetConfigProjectPath path
		// this error should never happen.
		return path
	}
	return rel
}

func (s *Service) GetConfigCMDByFileExtension(projectSubPath, imageCmd, ext string, tool tools.Tool) string {
	projectPath := s.GetConfigProjectPath()

	newProjectSubPath := file.GetSubPathByExtension(projectPath, projectSubPath, ext)
	if newProjectSubPath != "" {
		return s.AddWorkDirInCmd(imageCmd, newProjectSubPath, tool)
	}

	return s.AddWorkDirInCmd(imageCmd, projectSubPath, tool)
}

func (s *Service) IsDockerDisabled() bool {
	return s.config.DisableDocker
}

func (s *Service) GetCustomRulesByLanguage(lang languages.Language) []engine.Rule {
	return s.customRules.Load(lang)
}

func (s *Service) GetCustomImageByLanguage(language languages.Language) string {
	return s.config.CustomImages[language]
}

func (s *Service) IsOwaspDependencyCheckDisable() bool {
	return !s.config.EnableOwaspDependencyCheck
}

func (s *Service) IsShellcheckDisable() bool {
	return !s.config.EnableShellCheck
}

func (s *Service) IsSemanticEngineEnable() bool {
	return s.config.EnableSemanticEngine
}
