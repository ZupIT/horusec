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

package gosec

import (
	"errors"
	"testing"

	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/utils/testutil"

	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/services/formatters"
)

func TestGosecStartAnalysis(t *testing.T) {
	t.Run("Should run analysis successfully when output is empty", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", nil)

		cfg := config.New()

		entity := new(analysis.Analysis)
		service := formatters.NewFormatterService(entity, dockerAPIControllerMock, cfg)

		NewFormatter(service).StartAnalysis("")
		assert.False(t, entity.HasErrors(), "Expected no error for analysis")
	})

	t.Run("Should run analysis successfully and add vulnerability on Analysis", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")

		cfg := config.New()

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(outputAnalysis, nil)

		entity := new(analysis.Analysis)
		service := formatters.NewFormatterService(entity, dockerAPIControllerMock, cfg)

		gosec := NewFormatter(service)

		gosec.StartAnalysis("")

		assert.False(t, entity.HasErrors(), "Expected no errors for analysis")
		assert.Len(t, entity.AnalysisVulnerabilities, 5)
	})

	t.Run("Should run analysis and add error from Docker on Analysis", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("some error"))

		cfg := config.New()

		entity := new(analysis.Analysis)
		service := formatters.NewFormatterService(entity, dockerAPIControllerMock, cfg)

		gosec := NewFormatter(service)

		gosec.StartAnalysis("")
		assert.True(t, entity.HasErrors(), "Expected errors for analysis")
		assert.Equal(t, "some error", entity.Errors)
	})

	t.Run("Should run analysis and return error for an invalid output", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")

		outputAnalysis := "is some a text aleatory"

		cfg := config.New()

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(outputAnalysis, nil)

		entity := new(analysis.Analysis)
		service := formatters.NewFormatterService(entity, dockerAPIControllerMock, cfg)

		gosec := NewFormatter(service)
		gosec.StartAnalysis("")

		assert.True(t, entity.HasErrors(), "Expected errors for analysis")
	})

	t.Run("Should not execute gosec because it's ignored", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()

		cfg := config.New()
		cfg.ToolsConfig = toolsconfig.ToolsConfig{
			tools.GoSec: toolsconfig.Config{
				IsToIgnore: true,
			},
		}

		service := formatters.NewFormatterService(new(analysis.Analysis), dockerAPIControllerMock, cfg)
		gosec := NewFormatter(service)
		gosec.StartAnalysis("")
	})
}

const outputAnalysis = `
{
  "Golang errors": {
    "/go/src/code/api/server.go": [
      {
        "line": 20,
        "column": 42,
        "error": "Healthcheck not declared by package routes"
      }
    ]
  },
  "Issues": [
    {
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "cwe": {
        "ID": "327",
        "URL": "https://cwe.mitre.org/data/definitions/327.html"
      },
      "rule_id": "G501",
      "details": "Blacklisted import crypto/md5: weak cryptographic primitive",
      "file": "/go/src/code/api/util/util.go",
      "code": "\"crypto/md5\"",
      "line": "4",
      "column": "2"
    },
    {
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "cwe": {
        "ID": "326",
        "URL": "https://cwe.mitre.org/data/definitions/326.html"
      },
      "rule_id": "G401",
      "details": "Use of weak cryptographic primitive",
      "file": "/go/src/code/api/util/util.go",
      "code": "md5.New()",
      "line": "23",
      "column": "7"
    },
    {
      "severity": "LOW",
      "confidence": "HIGH",
      "cwe": {
        "ID": "703",
        "URL": "https://cwe.mitre.org/data/definitions/703.html"
      },
      "rule_id": "G104",
      "details": "Errors unhandled.",
      "file": "/go/src/code/api/util/util.go",
      "code": "io.WriteString(h, s)",
      "line": "24",
      "column": "2"
    },
    {
      "severity": "HIGH",
      "confidence": "HIGH",
      "cwe": {
        "ID": "746",
        "URL": "https://cwe.mitre.org/data/definitions/746.html"
      },
      "rule_id": "G746",
      "details": "Password hard codede",
      "file": "/go/src/code/api/server.go",
      "code": "password",
      "line": "2",
      "column": "6"
    },
    {
      "severity": "LOW",
      "confidence": "HIGH",
      "cwe": {
        "ID": "001",
        "URL": "https://cwe.mitre.org/data/definitions/001.html"
      },
      "rule_id": "G001",
      "details": "Rename Import",
      "file": "/go/src/code/api/server.go",
      "code": "cache := cache.NewCache() //nohorus",
      "line": "15",
      "column": "2"
    }
  ],
  "Stats": {
    "files": 4,
    "lines": 70,
    "found": 4
  }
}
		`
