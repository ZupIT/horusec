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
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	commitauthor "github.com/ZupIT/horusec/internal/entities/commit_author"

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

func (g *Git) CommitAuthor(line, filePath string) commitauthor.CommitAuthor {
	if !g.existsGitFolderInPath() || !g.config.EnableCommitAuthor {
		return g.newCommitAuthorNotFound()
	}
	return g.executeGitBlame(line, filePath)
}

func (g *Git) executeGitBlame(line, filePath string) commitauthor.CommitAuthor {
	if g.lineOrPathNotFound(line, filePath) {
		return g.newCommitAuthorNotFound()
	}
	output, err := g.executeCMD(line, filePath)
	if err != nil {
		return g.newCommitAuthorNotFound()
	}
	return g.parseOutput(output)
}

func (g *Git) lineOrPathNotFound(line, path string) bool {
	return line == "-" || path == "-" || line == "" || path == ""
}

func (g *Git) newCommitAuthorNotFound() commitauthor.CommitAuthor {
	return commitauthor.CommitAuthor{
		Author:     "-",
		Email:      "-",
		CommitHash: "-",
		Message:    "-",
		Date:       "-",
	}
}

//nolint:funlen
func (g *Git) executeCMD(line, filePath string) ([]byte, error) {
	lineAndPath := g.formatLineAndFilePath(g.getLine(line), filePath)

	stderr := bytes.NewBufferString("")

	// NOTE: Here we use ^ as json double quotes  to work properly on all platforms.
	cmd := exec.Command(
		"git",
		"log",
		"-1",
		`--format={
			^^^^^author^^^^^: ^^^^^%an^^^^^,
			^^^^^email^^^^^:^^^^^%ae^^^^^,
			^^^^^message^^^^^: ^^^^^%s^^^^^,
			^^^^^date^^^^^: ^^^^^%ci^^^^^,
			^^^^^commitHash^^^^^: ^^^^^%H^^^^^
		}`,
		lineAndPath,
	)
	cmd.Dir = g.config.ProjectPath
	cmd.Stderr = stderr

	response, err := cmd.Output()
	if err != nil {
		logger.LogErrorWithLevel(
			messages.MsgErrorGitCommitAuthorsExecute, err,
			map[string]interface{}{
				"line_and_path": lineAndPath,
				"stderr":        stderr.String(),
			})
	}

	return response, err
}

func (g *Git) parseOutput(output []byte) (author commitauthor.CommitAuthor) {
	output = g.getCleanOutput(output)
	if err := json.Unmarshal(output, &author); err != nil {
		logger.LogErrorWithLevel(
			messages.MsgErrorGitCommitAuthorsParseOutput+string(output), err,
		)
		return g.newCommitAuthorNotFound()
	}
	return author
}

func (g *Git) formatLineAndFilePath(line, filePath string) string {
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

func (g *Git) getCleanOutput(output []byte) []byte {
	// Output from git log contains the diff changes
	// so we need to extract only the json output data.
	if idx := bytes.LastIndex(output, []byte("}")); idx >= 0 {
		return bytes.ReplaceAll(output[:idx+1], []byte("^^^^^"), []byte(`"`))
	}
	logger.LogWarn(fmt.Sprintf("Could not to clean git blame output: %s", output))
	return []byte("")
}

func (g *Git) existsGitFolderInPath() bool {
	path := filepath.Join(g.config.ProjectPath, ".git")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}

	return true
}

// RepositoryIsShallow check if the ProjectPath is a shallow repository.
// A shallow repository is when a repository was cloned using the --depth=N
// where N is the number of commits that should be cloned.
//
// This git functionality is commonly used by CIs to clone the repository.
//
// For more read https://www.git-scm.com/docs/shallow
func RepositoryIsShallow(cfg *config.Config) bool {
	_, err := os.Stat(filepath.Join(cfg.ProjectPath, ".git", "shallow"))
	return !os.IsNotExist(err)
}
