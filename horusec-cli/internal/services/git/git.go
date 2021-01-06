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

package git

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/file"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
)

type IService interface {
	GetCommitAuthor(line, filePath string) (commitAuthor horusec.CommitAuthor)
}

type Service struct {
	config config.IConfig
}

func NewGitService(configs config.IConfig) IService {
	return &Service{
		config: configs,
	}
}

func (s *Service) GetCommitAuthor(line, filePath string) (commitAuthor horusec.CommitAuthor) {
	if !s.existsGitFolderInPath() {
		return s.getCommitAuthorNotFound()
	}
	if s.config.GetEnableCommitAuthor() {
		return s.executeGitBlame(line, filePath)
	}

	return s.getCommitAuthorNotFound()
}

func (s *Service) executeGitBlame(line, filePath string) (commitAuthor horusec.CommitAuthor) {
	if line == "" || filePath == "" {
		return s.getCommitAuthorNotFound()
	}
	if s.lineOrPathNotFound(line, filePath) {
		return s.getCommitAuthorNotFound()
	}
	output, err := s.executeCMD(line, filePath)
	if err != nil {
		return s.getCommitAuthorNotFound()
	}
	return s.parseOutputToStruct(output)
}

func (s *Service) lineOrPathNotFound(line, path string) bool {
	return line == "-" || path == "-" || line == "" || path == ""
}

func (s *Service) getCommitAuthorNotFound() horusec.CommitAuthor {
	return horusec.CommitAuthor{
		Author:     "-",
		Email:      "-",
		CommitHash: "-",
		Message:    "-",
		Date:       "-",
	}
}

func (s *Service) executeCMD(line, filePath string) ([]byte, error) {
	lineAndPath := s.setLineAndFilePath(s.getLine(line), filePath)
	cmd := exec.Command("git", "log", "-1", "--format={ %n  ^^^^^author^^^^^: ^^^^^%an^^^^^,%n"+
		"  ^^^^^email^^^^^:^^^^^%ae^^^^^,%n  ^^^^^message^^^^^: ^^^^^%s^^^^^,%n "+
		" ^^^^^date^^^^^: ^^^^^%ci^^^^^,%n  ^^^^^commitHash^^^^^:"+
		" ^^^^^%H^^^^^%n }", lineAndPath)

	cmd.Dir = s.config.GetProjectPath()
	response, err := cmd.Output()
	if err != nil {
		logger.LogErrorWithLevel(
			messages.MsgErrorGitCommitAuthorsExecute, err,
			map[string]interface{}{"line_and_path": lineAndPath})
	}
	return response, err
}

func (s *Service) parseOutputToStruct(output []byte) (commitAuthor horusec.CommitAuthor) {
	outputFormatted := s.getCleanOutput(output)
	if err := json.Unmarshal([]byte(outputFormatted), &commitAuthor); err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorGitCommitAuthorsParseOutput+outputFormatted,
			err)
		return s.getCommitAuthorNotFound()
	}
	return commitAuthor
}

func (s *Service) setLineAndFilePath(line, filePath string) string {
	return fmt.Sprintf("-L %s,%s:%s", line, line, filePath)
}

func (s *Service) getLine(line string) string {
	if !strings.Contains(line, "-") {
		return line
	}

	lines := strings.Split(line, "-")
	return lines[0]
}

func (s *Service) getCleanOutput(output []byte) string {
	outputToFormat := string(output)
	index := strings.Index(outputToFormat, "}")
	outputToFormat = outputToFormat[0 : index+1]
	outputToFormat = strings.ReplaceAll(outputToFormat, `"`, "")
	outputToFormat = strings.ReplaceAll(outputToFormat, "^^^^^", `"`)
	return outputToFormat
}

func (s *Service) existsGitFolderInPath() bool {
	if _, err := os.Stat(file.ReplacePathSeparator(s.config.GetProjectPath() + "/.git")); os.IsNotExist(err) {
		return false
	}

	return true
}
