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
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	engine "github.com/ZupIT/horusec-engine"

	commitauthor "github.com/ZupIT/horusec/internal/entities/commit_author"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/entities/vulnerability"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec/config"
	dockerentities "github.com/ZupIT/horusec/internal/entities/docker"
	"github.com/ZupIT/horusec/internal/entities/workdir"
	"github.com/ZupIT/horusec/internal/services/docker"
	"github.com/ZupIT/horusec/internal/services/engines/java"
)

func TestParseFindingsToVulnerabilities(t *testing.T) {
	analysis := new(analysis.Analysis)
	svc := NewFormatterService(analysis, &docker.Mock{}, config.New())

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
				Filename: "Test.java",
				Line:     10,
				Column:   20,
			},
		},
	}
	err := svc.ParseFindingsToVulnerabilities(findings, tools.HorusecEngine, languages.Java)
	require.Nil(t, err, "Expected nil error to parse finding to vulnerabilities")

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

func TestMock_AddWorkDirInCmd(t *testing.T) {
	mock := &Mock{}
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
		mock.SetAnalysisError(errors.New(""), "", "")
		_ = mock.RemoveSrcFolderFromPath("")
		_ = mock.GetCodeWithMaxCharacters("", 0)
	})
}

func TestExecuteContainer(t *testing.T) {
	t.Run("should return no error when success set is finished", func(t *testing.T) {
		analysis := &analysis.Analysis{}

		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("test", nil)

		monitorController := NewFormatterService(analysis, dockerAPIControllerMock, &config.Config{})
		result, err := monitorController.ExecuteContainer(&dockerentities.AnalysisData{})

		assert.NoError(t, err)
		assert.Equal(t, "test", result)
	})
}

func TestGetAnalysisIDErrorMessage(t *testing.T) {
	t.Run("should success get error message with replaces", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, &docker.Mock{}, &config.Config{})

		result := monitorController.GetAnalysisIDErrorMessage(tools.Bandit, "test")

		assert.NotEmpty(t, result)
		assert.Equal(t, "{HORUSEC_CLI} Something error went wrong in Bandit tool"+
			" | analysisID -> 00000000-0000-0000-0000-000000000000 | output -> test", result)
	})
}

func TestGetCommitAuthor(t *testing.T) {
	t.Run("should get commit author", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, &docker.Mock{}, &config.Config{})

		result := monitorController.GetCommitAuthor("", "")

		assert.NotEmpty(t, result)
	})
}

func TestGetConfigProjectPath(t *testing.T) {
	t.Run("should success get project path", func(t *testing.T) {
		cliConfig := &config.Config{
			StartOptions: config.StartOptions{
				ProjectPath: "test",
			},
		}

		svc := NewFormatterService(&analysis.Analysis{}, &docker.Mock{}, cliConfig)

		result := svc.GetConfigProjectPath()

		assert.NotEmpty(t, result)
		assert.Equal(t, filepath.Join("test", ".horusec", "00000000-0000-0000-0000-000000000000"), result)
	})
}

func TestAddWorkDirInCmd(t *testing.T) {
	t.Run("should success add workdir with no errors", func(t *testing.T) {
		cliConfig := &config.Config{}
		cliConfig.WorkDir = &workdir.WorkDir{
			CSharp: []string{"test"},
		}

		monitorController := NewFormatterService(&analysis.Analysis{}, &docker.Mock{}, cliConfig)

		result := monitorController.AddWorkDirInCmd("test", "C#", tools.SecurityCodeScan)

		assert.NotEmpty(t, result)
	})

	t.Run("should return cmd with no workdir", func(t *testing.T) {
		cliConfig := &config.Config{}
		cliConfig.WorkDir = &workdir.WorkDir{
			CSharp: []string{"test"},
		}

		monitorController := NewFormatterService(&analysis.Analysis{}, &docker.Mock{}, cliConfig)

		result := monitorController.AddWorkDirInCmd("test", "C#", tools.SecurityCodeScan)

		assert.NotEmpty(t, result)
	})
}

func TestLogDebugWithReplace(t *testing.T) {
	t.Run("should log debug and not panics", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, &docker.Mock{}, &config.Config{})

		assert.NotPanics(t, func() {
			monitorController.LogDebugWithReplace("test", tools.NpmAudit, languages.Javascript)
		})
	})
}

func TestGetAnalysisID(t *testing.T) {
	t.Run("should success get analysis id", func(t *testing.T) {
		id := uuid.New()
		monitorController := NewFormatterService(&analysis.Analysis{ID: id}, &docker.Mock{}, &config.Config{})
		assert.Equal(t, id.String(), monitorController.GetAnalysisID())
	})
}

func TestLogAnalysisError(t *testing.T) {
	t.Run("should not panic when logging error", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, &docker.Mock{}, &config.Config{})

		assert.NotPanics(t, func() {
			monitorController.SetAnalysisError(errors.New("test"), tools.GoSec, "")
		})
	})
	t.Run("should not panic when logging error and exists projectSubPath", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, &docker.Mock{}, &config.Config{})

		assert.NotPanics(t, func() {
			monitorController.SetAnalysisError(errors.New("test"), tools.GoSec, "/tmp")
		})
	})
}

func TestToolIsToIgnore(t *testing.T) {
	t.Run("should return true when language is match", func(t *testing.T) {
		configs := &config.Config{}
		configs.ToolsConfig = toolsconfig.ParseInterfaceToMapToolsConfig(
			toolsconfig.ToolsConfigsStruct{GoSec: toolsconfig.ToolConfig{IsToIgnore: true}},
		)

		monitorController := NewFormatterService(&analysis.Analysis{}, &docker.Mock{}, configs)

		assert.Equal(t, true, monitorController.ToolIsToIgnore(tools.GoSec))
	})
	t.Run("should return true when language is match uppercase", func(t *testing.T) {
		configs := &config.Config{}
		configs.ToolsConfig = toolsconfig.ParseInterfaceToMapToolsConfig(
			toolsconfig.ToolsConfigsStruct{GoSec: toolsconfig.ToolConfig{IsToIgnore: true}},
		)

		monitorController := NewFormatterService(&analysis.Analysis{}, &docker.Mock{}, configs)

		assert.Equal(t, true, monitorController.ToolIsToIgnore(tools.GoSec))
	})
	t.Run("should return true when language is match lowercase and multi tools", func(t *testing.T) {
		configs := &config.Config{}
		configs.ToolsConfig = toolsconfig.ParseInterfaceToMapToolsConfig(
			toolsconfig.ToolsConfigsStruct{
				GoSec:            toolsconfig.ToolConfig{IsToIgnore: true},
				SecurityCodeScan: toolsconfig.ToolConfig{IsToIgnore: true},
			},
		)

		monitorController := NewFormatterService(&analysis.Analysis{}, &docker.Mock{}, configs)

		assert.Equal(t, true, monitorController.ToolIsToIgnore(tools.GoSec))
	})
	t.Run("should return false when language is not match", func(t *testing.T) {
		configs := &config.Config{}
		configs.ToolsConfig = toolsconfig.ParseInterfaceToMapToolsConfig(
			toolsconfig.ToolsConfigsStruct{SecurityCodeScan: toolsconfig.ToolConfig{IsToIgnore: true}},
		)

		monitorController := NewFormatterService(&analysis.Analysis{}, &docker.Mock{}, configs)

		assert.Equal(t, false, monitorController.ToolIsToIgnore(tools.GoSec))
	})
}

func TestService_GetCodeWithMaxCharacters(t *testing.T) {
	t.Run("should return default code", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, &docker.Mock{}, &config.Config{})
		code := "text"
		column := 0
		newCode := monitorController.GetCodeWithMaxCharacters(code, column)
		assert.Equal(t, "text", newCode)
	})
	t.Run("should return default code if column is negative", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, &docker.Mock{}, &config.Config{})
		code := "text"
		column := -1
		newCode := monitorController.GetCodeWithMaxCharacters(code, column)
		assert.Equal(t, "text", newCode)
	})
	t.Run("should return 4:105 characters when text is so bigger", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, &docker.Mock{}, &config.Config{})
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
		monitorController := NewFormatterService(&analysis.Analysis{}, &docker.Mock{}, &config.Config{})
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
		monitorController := NewFormatterService(&analysis.Analysis{}, &docker.Mock{}, &config.Config{})
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
		monitorController := NewFormatterService(&analysis.Analysis{}, &docker.Mock{}, &config.Config{})
		code := "text"
		for i := 0; i <= 200; i++ {
			code += strconv.Itoa(i)
		}
		column := 74
		newCode := monitorController.GetCodeWithMaxCharacters(code, column)
		assert.Equal(t, "4041424344454647484950515253545556575859606162636465666768697071727374757677787980818283848586878889", newCode)
	})
	t.Run("should return first 100 characters when text is so bigger", func(t *testing.T) {
		monitorController := NewFormatterService(&analysis.Analysis{}, &docker.Mock{}, &config.Config{})
		code := "text"
		for i := 0; i <= 200; i++ {
			code += strconv.Itoa(i)
		}
		column := 999
		newCode := monitorController.GetCodeWithMaxCharacters(code, column)
		assert.Len(t, newCode, 100)
	})
}
