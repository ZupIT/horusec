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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ZupIT/horusec/config"
	commitauthor "github.com/ZupIT/horusec/internal/entities/commit_author"
	dockerentities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/entities/workdir"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/services/engines/java"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestParseFindingsToVulnerabilities(t *testing.T) {
	analysis := &analysis.Analysis{
		ID: uuid.New(),
	}
	cfg := config.New()
	svc := NewFormatterService(analysis, testutil.NewDockerMock(), cfg)

	rule := java.NewAWSQueryInjection()
	findings := []engine.Finding{
		{
			ID:          rule.ID,
			Name:        rule.Name,
			Severity:    rule.Severity,
			CodeSample:  "testing",
			Confidence:  rule.Confidence,
			Description: rule.Description,
			SourceLocation: engine.Location{
				Filename: filepath.Join(cfg.ProjectPath, ".horusec", analysis.ID.String(), "Test.java"),
				Line:     10,
				Column:   20,
			},
		},
	}
	svc.ParseFindingsToVulnerabilities(findings, tools.HorusecEngine, languages.Java)

	expectedVulnerabilities := []vulnerability.Vulnerability{
		{
			RuleID:        rule.ID,
			Line:          "10",
			Column:        "20",
			Confidence:    confidence.Confidence(rule.Confidence),
			File:          "Test.java",
			Code:          "testing",
			Details:       fmt.Sprintf("%s\n%s", rule.Name, rule.Description),
			SecurityTool:  tools.HorusecEngine,
			Language:      languages.Java,
			Severity:      severities.GetSeverityByString(rule.Severity),
			CommitAuthor:  "-",
			CommitDate:    "-",
			CommitEmail:   "-",
			CommitHash:    "-",
			CommitMessage: "-",
			// NOTE: We hard coded vulnerability hash here to assert that we are not breaking existing hashes
			VulnHash:        "b9ffd6959275a840254c9ddc9ab0cc5edd6f7950f1b71103d772ac5a17ca988d",
			VulnHashInvalid: "7ebe9a1e2b39735edcae2f576f31ea4779b5eb9300064e3ebb351069fdd01ed3",
		},
	}

	require.Len(t, analysis.AnalysisVulnerabilities, len(expectedVulnerabilities))
	for idx := range expectedVulnerabilities {
		assert.Equal(t, expectedVulnerabilities[idx], analysis.AnalysisVulnerabilities[idx].Vulnerability)
	}
}

func TestSetAnalysisError(t *testing.T) {
	analysis := new(analysis.Analysis)
	svc := NewFormatterService(analysis, testutil.NewDockerMock(), config.New())

	svc.SetAnalysisError(errors.New("some error"), tools.HorusecEngine, "testing", "")
	svc.SetAnalysisError(errors.New("other error"), tools.HorusecEngine, "testing 2", "")

	expectedErrors := "Error while running tool HorusecEngine: some error; Error while running tool HorusecEngine: other error"

	assert.Equal(t, expectedErrors, analysis.Errors)
}

func TestMock_AddWorkDirInCmd(t *testing.T) {
	mock := testutil.NewFormatterMock()
	t.Run("Should mock with success", func(t *testing.T) {
		mock.On("LogDebugWithReplace")
		mock.On("GetAnalysisID").Return("")
		mock.On("SetAnalysisError").Return()
		mock.On("ExecuteContainer").Return("", nil)
		mock.On("GetAnalysisIDErrorMessage").Return("")
		mock.On("GetCommitAuthor").Return(commitauthor.CommitAuthor{})
		mock.On("AddWorkDirInCmd").Return("")
		mock.On("GetConfigProjectPath").Return("")
		mock.On("GetAnalysis").Return(&analysis.Analysis{})
		mock.On("SetToolFinishedAnalysis").Return()
		mock.On("LogAnalysisError").Return()
		mock.On("SetMonitor").Return()
		mock.On("RemoveSrcFolderFromPath").Return("")
		mock.On("GetCodeWithMaxCharacters").Return("")
		mock.LogDebugWithReplace("", "", "")
		_ = mock.GetAnalysisID()
		_, _ = mock.ExecuteContainer(&dockerentities.AnalysisData{})
		_ = mock.GetAnalysisIDErrorMessage("", "")
		_ = mock.GetCommitAuthor("", "")
		_ = mock.AddWorkDirInCmd("", "", "")
		_ = mock.GetConfigProjectPath()
		mock.SetAnalysisError(errors.New(""), "", "", "")
		_ = mock.RemoveSrcFolderFromPath("")
		_ = mock.GetCodeWithMaxCharacters("", 0)
	})
}

func TestExecuteContainer(t *testing.T) {
	t.Run("should return no error when execute container", func(t *testing.T) {
		analysis := &analysis.Analysis{}

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("test", nil)

		monitorController := NewFormatterService(analysis, dockerAPIControllerMock, &config.Config{})
		result, err := monitorController.ExecuteContainer(&dockerentities.AnalysisData{})

		assert.NoError(t, err)
		assert.Equal(t, "test", result)
	})
	t.Run("should return error when execute container if CreateLanguageAnalysisContainer return error", func(t *testing.T) {
		analysis := &analysis.Analysis{}

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("test", errors.New("some error"))

		monitorController := NewFormatterService(analysis, dockerAPIControllerMock, &config.Config{})
		result, err := monitorController.ExecuteContainer(&dockerentities.AnalysisData{})

		assert.Error(t, err)
		assert.Equal(t, "test", result)
		assert.Equal(t, err.Error(), "some error")
	})
}

func TestGetAnalysisIDErrorMessage(t *testing.T) {
	t.Run("should success get error message with replaces", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), &config.Config{})

		result := monitorController.GetAnalysisIDErrorMessage(tools.Bandit, "test")

		assert.NotEmpty(t, result)
		assert.Equal(t, "{HORUSEC_CLI} Something error went wrong in Bandit tool"+
			" | analysisID -> 00000000-0000-0000-0000-000000000000 | output -> test", result)
	})
}

func TestGetCommitAuthor(t *testing.T) {
	t.Run("should get commit author default values when .git folder is not found", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), &config.Config{})

		result := monitorController.GetCommitAuthor("", "")
		assert.Equal(t, "-", result.Author)
		assert.Equal(t, "-", result.CommitHash)
		assert.Equal(t, "-", result.Date)
		assert.Equal(t, "-", result.Email)
		assert.Equal(t, "-", result.Message)
		assert.NotEmpty(t, result)
	})
	t.Run("should get commit author values when .git folder is found", func(t *testing.T) {
		cfg := &config.Config{
			StartOptions: config.StartOptions{
				ProjectPath:        testutil.ExamplesPath,
				EnableCommitAuthor: true,
			},
		}
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), cfg)

		result := monitorController.GetCommitAuthor("15", filepath.Join(testutil.GoExample1, "api", "server.go"))
		notExpected := commitauthor.CommitAuthor{
			Author:     "-",
			Email:      "-",
			CommitHash: "-",
			Message:    "-",
			Date:       "-",
		}
		assert.NotEmpty(t, result)
		assert.NotEqual(t, notExpected, result)
	})
}

func TestGetConfigProjectPath(t *testing.T) {
	t.Run("should success get project path", func(t *testing.T) {
		cliConfig := &config.Config{
			StartOptions: config.StartOptions{
				ProjectPath: "test",
			},
		}

		svc := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), cliConfig)

		result := svc.GetConfigProjectPath()

		assert.NotEmpty(t, result)
		assert.Equal(t, filepath.Join("test", ".horusec", "00000000-0000-0000-0000-000000000000"), result)
	})
}

func TestAddWorkDirInCmd(t *testing.T) {
	t.Run("should success add workdir with no errors", func(t *testing.T) {
		workDirString := "{{WORK_DIR}} "
		cmd := "testcmd"
		cmdWithWorkDir := workDirString + cmd
		projectSubPath := filepath.Join("random", "file", "path")

		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), &config.Config{})

		result := monitorController.AddWorkDirInCmd(cmdWithWorkDir, projectSubPath, tools.SecurityCodeScan)

		expectedString := fmt.Sprintf("cd random/file/path %s", cmd)

		assert.Equal(t, expectedString, result)
	})

	t.Run("should return cmd with no workdir", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), &config.Config{})
		cmd := "testcmd"
		result := monitorController.AddWorkDirInCmd(cmd, "", tools.SecurityCodeScan)

		assert.Equal(t, cmd, result)
	})
}

func TestLogDebugWithReplace(t *testing.T) {
	t.Run("should log debug and not panics", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), &config.Config{})
		stdOutMock := bytes.NewBufferString("")
		logger.LogSetOutput(stdOutMock)
		logger.SetLogLevel("debug")
		assert.NotPanics(t, func() {
			monitorController.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.NpmAudit, languages.Javascript)
		})
		assert.Contains(t, stdOutMock.String(), `level=debug msg="{HORUSEC_CLI} Running NpmAudit - JavaScript in analysisID: [00000000-0000-0000-0000-000000000000]`)
	})
}

func TestGetAnalysisID(t *testing.T) {
	t.Run("should success get analysis id", func(t *testing.T) {
		id := uuid.New()
		monitorController := NewFormatterService(&analysis.Analysis{ID: id}, testutil.NewDockerMock(), &config.Config{})
		assert.Equal(t, id.String(), monitorController.GetAnalysisID())
	})
}

func TestLogAnalysisError(t *testing.T) {
	t.Run("should not panic when logging error", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), &config.Config{})
		stdOutMock := bytes.NewBufferString("")
		logger.LogSetOutput(stdOutMock)
		logger.SetLogLevel("debug")
		assert.NotPanics(t, func() {
			monitorController.SetAnalysisError(errors.New("test"), tools.GoSec, "container err", "")
			monitorController.SetAnalysisError(errors.New("test2"), tools.GitLeaks, "container err", "")
		})
		assert.Contains(t, stdOutMock.String(), `{HORUSEC_CLI} Something error went wrong in GoSec tool | analysisID -> 00000000-0000-0000-0000-000000000000 | output -> container err`)
	})
	t.Run("should not panic when logging error and exists projectSubPath", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), &config.Config{})
		stdOutMock := bytes.NewBufferString("")
		logger.LogSetOutput(stdOutMock)
		logger.SetLogLevel("debug")
		assert.NotPanics(t, func() {
			monitorController.SetAnalysisError(errors.New("test"), tools.GoSec, "container err", "/tmp")
			monitorController.SetAnalysisError(errors.New("test2"), tools.GitLeaks, "container err", "/tmp")
		})
		assert.Contains(t, stdOutMock.String(), `{HORUSEC_CLI} Something error went wrong in GoSec tool | analysisID -> 00000000-0000-0000-0000-000000000000 | output -> container err | ProjectSubPath -> /tmp - test"`)
	})
}

func TestToolIsToIgnore(t *testing.T) {
	t.Run("should return true when language is match", func(t *testing.T) {
		configs := &config.Config{}
		configs.ToolsConfig = toolsconfig.ToolsConfig{
			tools.GoSec: toolsconfig.Config{
				IsToIgnore: true,
			},
		}

		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), configs)

		assert.Equal(t, true, monitorController.ToolIsToIgnore(tools.GoSec))
	})
	t.Run("should return true when language is match uppercase", func(t *testing.T) {
		configs := &config.Config{}
		configs.ToolsConfig = toolsconfig.ToolsConfig{
			tools.GoSec: toolsconfig.Config{
				IsToIgnore: true,
			},
		}

		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), configs)

		assert.Equal(t, true, monitorController.ToolIsToIgnore(tools.GoSec))
	})
	t.Run("should return true when language is match lowercase and multi tools", func(t *testing.T) {
		configs := &config.Config{}
		configs.ToolsConfig = toolsconfig.ToolsConfig{
			tools.GoSec:            toolsconfig.Config{IsToIgnore: true},
			tools.SecurityCodeScan: toolsconfig.Config{IsToIgnore: true},
		}

		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), configs)

		assert.Equal(t, true, monitorController.ToolIsToIgnore(tools.GoSec))
	})
	t.Run("should return false when language is not match", func(t *testing.T) {
		configs := &config.Config{}
		configs.ToolsConfig = toolsconfig.ToolsConfig{
			tools.SecurityCodeScan: toolsconfig.Config{
				IsToIgnore: true,
			},
		}

		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), configs)

		assert.Equal(t, false, monitorController.ToolIsToIgnore(tools.GoSec))
	})
	t.Run("should return false when language not exists", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), &config.Config{})

		assert.Equal(t, false, monitorController.ToolIsToIgnore(tools.GoSec))
	})
}

func TestService_GetCodeWithMaxCharacters(t *testing.T) {
	t.Run("should return default code", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), &config.Config{})
		code := "text"
		column := 0
		newCode := monitorController.GetCodeWithMaxCharacters(code, column)
		assert.Equal(t, "text", newCode)
	})
	t.Run("should return default code if column is negative", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), &config.Config{})
		code := "text"
		column := -1
		newCode := monitorController.GetCodeWithMaxCharacters(code, column)
		assert.Equal(t, "text", newCode)
	})
	t.Run("should return 4:105 characters when text is so bigger", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), &config.Config{})
		code := "text"
		for i := 0; i < 10; i++ {
			for i := 0; i <= 9; i++ {
				code += strconv.Itoa(i)
			}
		}
		column := 4
		newCode := monitorController.GetCodeWithMaxCharacters(code, column)
		assert.Equal(t, "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789", newCode)
	})
	t.Run("should return first 100 characters when text is so bigger", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), &config.Config{})
		code := "text"
		for i := 0; i < 10; i++ {
			for i := 0; i <= 9; i++ {
				code += strconv.Itoa(i)
			}
		}
		column := 0
		newCode := monitorController.GetCodeWithMaxCharacters(code, column)
		assert.Equal(t, "text012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345", newCode)
	})
	t.Run("should return first 100 characters when text contains breaking lines", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), &config.Config{})
		code := `22: func GetMD5(s string) string {
23:     h := md5.New()
24:     io.WriteString(h, s) // #nohorus
		`
		column := 0
		newCode := monitorController.GetCodeWithMaxCharacters(code, column)
		assert.Equal(t, `22: func GetMD5(s string) string {
23:     h := md5.New()
24:     io.WriteString(h, s) // #nohorus
	`, newCode)
	})
	t.Run("should return first 100 characters when text is so bigger", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), &config.Config{})
		code := "text"
		for i := 0; i <= 200; i++ {
			code += strconv.Itoa(i)
		}
		column := 74
		newCode := monitorController.GetCodeWithMaxCharacters(code, column)
		assert.Equal(t, "4041424344454647484950515253545556575859606162636465666768697071727374757677787980818283848586878889", newCode)
	})
	t.Run("should return first 100 characters when text is so bigger", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), &config.Config{})
		code := "text"
		for i := 0; i <= 200; i++ {
			code += strconv.Itoa(i)
		}
		column := 999
		newCode := monitorController.GetCodeWithMaxCharacters(code, column)
		assert.Len(t, newCode, 100)
	})
}

func TestRemoveSrcFolderFromPath(t *testing.T) {
	t.Run("should return path without src prefix", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), &config.Config{})
		result := monitorController.RemoveSrcFolderFromPath(filepath.Join("/", "src", "something"))
		assert.Equal(t, filepath.Base("something"), result)
	})
	t.Run("should return path without src prefix", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), &config.Config{})
		result := monitorController.RemoveSrcFolderFromPath(filepath.Join("/", "src", "something", "test"))
		assert.Equal(t, filepath.Join("something", "test"), result)
	})
	t.Run("should return path without diff when src is after 4 index position", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), &config.Config{})
		result := monitorController.RemoveSrcFolderFromPath(filepath.Join("something", "src"))
		assert.Equal(t, filepath.Join("something", "src"), result)
	})
	t.Run("should return path without diff when src is before 4 index position", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), &config.Config{})
		result := monitorController.RemoveSrcFolderFromPath(filepath.Base("src"))
		assert.Equal(t, filepath.Base("src"), result)
	})
}

func TestGetFilepathFromFilename(t *testing.T) {
	t.Run("should successfully return path from filename", func(t *testing.T) {
		cfg := &config.Config{
			StartOptions: config.StartOptions{
				ProjectPath: testutil.GoExample1,
			},
		}
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), cfg)
		dirName := filepath.Join(cfg.ProjectPath, ".horusec", monitorController.GetAnalysisID())
		relativeFilePath := filepath.Join("examples", "go", "example1")
		filename := "server.go"

		err := os.MkdirAll(filepath.Join(dirName, relativeFilePath), 0o700)
		assert.NoError(t, err)

		file, err := os.Create(filepath.Join(dirName, relativeFilePath, filename))
		assert.NotNil(t, file)
		assert.NoError(t, err)

		result, err := monitorController.GetFilepathFromFilename(filename, "")

		assert.Equal(t, filepath.Join(relativeFilePath, filename), result)
		t.Cleanup(func() {
			_ = file.Close()
			_ = os.RemoveAll(dirName)
		})
	})
	t.Run("should return empty when path from filename is not found", func(t *testing.T) {
		cfg := &config.Config{
			StartOptions: config.StartOptions{
				ProjectPath: testutil.GoExample1,
			},
		}
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), cfg)
		filename := "server.go"

		result, err := monitorController.GetFilepathFromFilename(filename, "")
		assert.Error(t, err)
		assert.Equal(t, "", result)
	})
}

func TestGetConfigCMDByFileExtension(t *testing.T) {
	t.Run("should return path when valid parameters", func(t *testing.T) {
		cfg := &config.Config{
			StartOptions: config.StartOptions{
				ProjectPath: testutil.GoExample1,
				WorkDir:     &workdir.WorkDir{Go: []string{"a", "b"}},
			},
		}

		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), cfg)

		dirName := filepath.Join(cfg.ProjectPath, ".horusec", monitorController.GetAnalysisID())
		relativeFilePath := filepath.Join("examples", "go", "example1")
		filename := "package-lock.json"

		err := os.MkdirAll(filepath.Join(dirName, relativeFilePath), 0o700)
		assert.NoError(t, err)

		file, err := os.Create(filepath.Join(dirName, relativeFilePath, filename))
		assert.NoError(t, err)

		cmdWithWorkdir := `
 	  {{WORK_DIR}}
      if [ -f package-lock.json ]; then
        npm audit --only=prod --json > /tmp/results-ANALYSISID.json 2> /tmp/errorNpmaudit-ANALYSISID
        jq -j -M -c . /tmp/results-ANALYSISID.json
      else
        if [ ! -f yarn.lock ]; then
          echo 'ERROR_PACKAGE_LOCK_NOT_FOUND'
        fi
      fi
  `
		expectedCmd := `
 	  cd examples/go/example1
      if [ -f package-lock.json ]; then
        npm audit --only=prod --json > /tmp/results-ANALYSISID.json 2> /tmp/errorNpmaudit-ANALYSISID
        jq -j -M -c . /tmp/results-ANALYSISID.json
      else
        if [ ! -f yarn.lock ]; then
          echo 'ERROR_PACKAGE_LOCK_NOT_FOUND'
        fi
      fi
  `
		result := monitorController.GetConfigCMDByFileExtension(relativeFilePath, cmdWithWorkdir, "package-lock.json", tools.NpmAudit)

		assert.Equal(t, expectedCmd, result)
		t.Cleanup(func() {
			_ = file.Close()
			_ = os.RemoveAll(dirName)
		})
	})
	t.Run("should return cmd when cmd has no workdir", func(t *testing.T) {
		cfg := &config.Config{
			StartOptions: config.StartOptions{
				ProjectPath: testutil.GoExample1,
			},
		}
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), cfg)
		expectedCmd := "expectedCmd"
		result := monitorController.GetConfigCMDByFileExtension("relativeFilePath", expectedCmd, "package-lock.json", tools.NpmAudit)
		assert.Equal(t, expectedCmd, result)
	})
	t.Run("should return cmd with altered workdir when cmd has workdir", func(t *testing.T) {
		cfg := &config.Config{
			StartOptions: config.StartOptions{
				ProjectPath: testutil.GoExample1,
			},
		}
		monitorController := NewFormatterService(&analysis.Analysis{}, testutil.NewDockerMock(), cfg)
		workdirString := "{{WORK_DIR}}"
		cmd := "expectedCmd"
		relativeFilePath := "relativeFilePath"
		expectedResult := "cd " + relativeFilePath + cmd
		result := monitorController.GetConfigCMDByFileExtension(relativeFilePath, workdirString+cmd, "package-lock.json", tools.NpmAudit)
		assert.Equal(t, expectedResult, result)
	})
}
