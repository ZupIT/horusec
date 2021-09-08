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
	"strconv"
	"strings"

	commitAuthor "github.com/ZupIT/horusec/internal/entities/commit_author"
	"github.com/ZupIT/horusec/internal/utils/file"

	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/helpers/messages"
)

type Git struct {
	config *config.Config
}

func New(cfg *config.Config) *Git {
	return &Git{
		config: cfg,
	}
}

func (g *Git) CommitAuthor(line, filePath string) commitAuthor.CommitAuthor {
	if !g.existsGitFolderInPath() {
		return g.getCommitAuthorNotFound()
	}
	if g.config.GetEnableCommitAuthor() {
		return g.executeGitBlame(line, filePath)
	}

	return g.getCommitAuthorNotFound()
}

func (g *Git) executeGitBlame(line, filePath string) commitAuthor.CommitAuthor {
	if line == "" || filePath == "" {
		return g.getCommitAuthorNotFound()
	}
	if g.lineOrPathNotFound(line, filePath) {
		return g.getCommitAuthorNotFound()
	}
	output, err := g.executeCMD(line, filePath)
	if err != nil {
		return g.getCommitAuthorNotFound()
	}
	return g.parseOutputToStruct(output)
}

func (g *Git) lineOrPathNotFound(line, path string) bool {
	return line == "-" || path == "-" || line == "" || path == ""
}

func (g *Git) getCommitAuthorNotFound() commitAuthor.CommitAuthor {
	return commitAuthor.CommitAuthor{
		Author:     "-",
		Email:      "-",
		CommitHash: "-",
		Message:    "-",
		Date:       "-",
	}
}

func (g *Git) executeCMD(line, filePath string) ([]byte, error) {
	lineAndPath := g.setLineAndFilePath(g.getLine(line), filePath)
	cmd := exec.Command("git", "log", "-1", "--format={ %n  ^^^^^author^^^^^: ^^^^^%an^^^^^,%n"+
		"  ^^^^^email^^^^^:^^^^^%ae^^^^^,%n  ^^^^^message^^^^^: ^^^^^%s^^^^^,%n "+
		" ^^^^^date^^^^^: ^^^^^%ci^^^^^,%n  ^^^^^commitHash^^^^^:"+
		" ^^^^^%H^^^^^%n }", lineAndPath)

	cmd.Dir = g.config.GetProjectPath()
	response, err := cmd.Output()
	if err != nil {
		logger.LogErrorWithLevel(
			messages.MsgErrorGitCommitAuthorsExecute, err,
			map[string]interface{}{"line_and_path": lineAndPath})
	}
	return response, err
}

func (g *Git) parseOutputToStruct(output []byte) (author commitAuthor.CommitAuthor) {
	outputFormatted := g.getCleanOutput(output)
	if err := json.Unmarshal([]byte(outputFormatted), &author); err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorGitCommitAuthorsParseOutput+outputFormatted,
			err)
		return g.getCommitAuthorNotFound()
	}
	return author
}

func (g *Git) setLineAndFilePath(line, filePath string) string {
	return fmt.Sprintf("-L %s,%s:%s", line, line, filePath)
}

func (g *Git) getLine(line string) string {
	if !strings.Contains(line, "-") {
		return g.parseLineStringToNumber(line)
	}

	lines := strings.Split(line, "-")
	return g.parseLineStringToNumber(lines[0])
}

func (g *Git) parseLineStringToNumber(line string) string {
	num, err := strconv.Atoi(line)
	if err != nil {
		return "1"
	}
	if num <= 0 {
		return "1"
	}
	return strconv.Itoa(num)
}

func (g *Git) getCleanOutput(output []byte) string {
	outputToFormat := string(output)
	index := strings.Index(outputToFormat, "}")
	outputToFormat = outputToFormat[0 : index+1]
	outputToFormat = strings.ReplaceAll(outputToFormat, `"`, "")
	outputToFormat = strings.ReplaceAll(outputToFormat, "^^^^^", `"`)
	return outputToFormat
}

func (g *Git) existsGitFolderInPath() bool {
	path := fmt.Sprintf("%s/.git", g.config.GetProjectPath())
	if _, err := os.Stat(file.ReplacePathSeparator(path)); os.IsNotExist(err) {
		return false
	}

	return true
}
