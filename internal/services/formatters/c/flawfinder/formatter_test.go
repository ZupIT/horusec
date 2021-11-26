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

package flawfinder

import (
	"bytes"
	"encoding/csv"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestStartCFlawfinder(t *testing.T) {
	t.Run("should run analysis successfully when output is empty", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		cfg := config.New()

		output := csvOutput(t, cfg.ProjectPath)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")

		require.Len(t, analysis.AnalysisVulnerabilities, 1)

		vuln := analysis.AnalysisVulnerabilities[0].Vulnerability

		assert.Equal(t, tools.Flawfinder, vuln.SecurityTool, "Expected flawfinder as security tool")
		assert.Equal(t, languages.C, vuln.Language, "Expected C as vulnerability language")
		assert.Equal(t, severities.Critical, vuln.Severity, "Exected critial as vulnerability severity")
		assert.Equal(t, "waring suggestion note", vuln.Details, "Exected equals vulnerability details")
		assert.Equal(t, "16", vuln.Line, "Exected equals vulnerability line")
		assert.Equal(t, "9", vuln.Column, "Exected equals vulnerability column")
		assert.Equal(
			t,
			`char BOM[4] = {(char)0xEF, (char)0xBB, (char)0xBF, '\0'};`,
			vuln.Code,
			"Exected equals vulnerability code",
		)
		assert.Equal(t, filepath.Join(cfg.ProjectPath, "test.c"), vuln.File)
	})

	t.Run("should add error on analysis when invalid output", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		cfg := config.New()

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")

		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("should run analysis and add error from Docker on Analysis", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		cfg := config.New()

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")

		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("Should not execute tool because it's ignored", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()

		config := config.New()
		config.ToolsConfig = toolsconfig.ToolsConfig{
			tools.Flawfinder: toolsconfig.Config{
				IsToIgnore: true,
			},
		}

		service := formatters.NewFormatterService(new(analysis.Analysis), dockerAPIControllerMock, config)
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")
	})
}

func csvOutput(t *testing.T, basePath string) string {
	pairs := [][]string{
		{
			"File",
			"Line",
			"Column",
			"Level",
			"Category",
			"Name",
			"Warning",
			"Suggestion",
			"Note",
			"CWEs",
			"Context",
			"Fingerprint",
		},
		{
			filepath.Join(basePath, "test.c"), // File
			"16",                              // Line
			"9",                               // Column
			"5",                               // Level
			"4",                               // Category
			"char",                            // Name
			"waring",                          // Warning
			"suggestion",                      // Suggestion
			"note",                            // Note
			"CWE-123",                         // CWEs
			`char BOM[4] = {(char)0xEF, (char)0xBB, (char)0xBF, '\0'};`, // Context
			"fingerprint", // Fingerprint
		},
	}

	buffer := bytes.NewBufferString("")
	writer := csv.NewWriter(buffer)

	require.NoError(t, writer.WriteAll(pairs), "Expected no errors to create csv mock")

	return buffer.String()
}
