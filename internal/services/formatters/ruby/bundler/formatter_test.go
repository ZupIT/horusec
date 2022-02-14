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

package bundler

import (
	"errors"
	"testing"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestParseOutput(t *testing.T) {
	t.Run("should add 2 vulnerabilities on analysis with no errors", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, newTestConfig(t, analysis))
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.Len(t, analysis.AnalysisVulnerabilities, 2)
		for _, v := range analysis.AnalysisVulnerabilities {
			vuln := v.Vulnerability
			assert.Equal(t, tools.BundlerAudit, vuln.SecurityTool)
			assert.Equal(t, languages.Ruby, vuln.Language)
			assert.Equal(t, confidence.Low, vuln.Confidence)
			assert.NotEmpty(t, vuln.Details, "Exepcted not empty details")
			assert.NotContains(t, vuln.Details, "()")
			assert.NotEmpty(t, vuln.File, "Expected not empty file name")
			assert.NotEmpty(t, vuln.Line, "Expected not empty line")
			assert.NotEmpty(t, vuln.Severity, "Expected not empty severity")
		}
	})

	t.Run("should add error and no vulnerabilities on analysis when parse invalid output", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("invalid output", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, newTestConfig(t, analysis))
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, analysis.HasErrors(), "Expected no errors on analysis")
		assert.Len(t, analysis.AnalysisVulnerabilities, 0)
	})

	t.Run("Should add error on analysis when Gemfile.lock not found", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(`Could not find "Gemfile.lock"`, nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, newTestConfig(t, analysis))
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("Should add no vulnerabilities on analysis when empty", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("No vulnerabilities found", nil)

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, newTestConfig(t, analysis))
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.False(t, analysis.HasErrors(), "Expected no errors on analysis")
		assert.Len(t, analysis.AnalysisVulnerabilities, 0)
	})

	t.Run("Should add error on analysis when something went wrong in container", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("test"))

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, newTestConfig(t, analysis))
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("Should not execute tool because it's ignored", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()
		cfg := config.New()
		cfg.ToolsConfig = toolsconfig.ToolsConfig{
			tools.BundlerAudit: toolsconfig.Config{
				IsToIgnore: true,
			},
		}

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")
	})
}

func newTestConfig(t *testing.T, analysiss *analysis.Analysis) *config.Config {
	cfg := config.New()
	cfg.ProjectPath = testutil.CreateHorusecAnalysisDirectory(t, analysiss, testutil.RubyExample1)
	return cfg
}

// output contains the expected output from bundler
//
// Note, output from bundler is colored, and the formatter remove this colors
// before the parsing, so the expected output.
//
// This output has the following schema:
//
// Name: actionpack
// Version: 6.0.0
// Advisory: CVE-2020-8164
// Criticality: Unknown
// URL: https://groups.google.com/forum/#!topic/rubyonrails-security/f6ioe4sdpbY
// Title: Possible Strong Parameters Bypass in ActionPack
// Solution: upgrade to ~> 5.2.4.3, >= 6.0.3.1
//
const output = "\u001B[31mName: \u001B[0mactionpack\n\u001B[31mVersion: \u001B[0m6.0.0\n\u001B[31mAdvisory: \u001B[0mCVE-2020-8164\n\u001B[31mCriticality: \u001B[0mUnknown\n\u001B[31mURL: \u001B[0mhttps://groups.google.com/forum/#!topic/rubyonrails-security/f6ioe4sdpbY\n\u001B[31mTitle: \u001B[0mPossible Strong Parameters Bypass in ActionPack\n\u001B[31mSolution: upgrade to \u001B[0m~> 5.2.4.3, >= 6.0.3.1\n\n\u001B[31mName: \u001B[0mactionpack\n\u001B[31mVersion: \u001B[0m6.0.0\n\u001B[31mAdvisory: \u001B[0mCVE-2020-8166\n\u001B[31mCriticality: \u001B[0mUnknown\n\u001B[31mURL: \u001B[0mhttps://groups.google.com/forum/#!topic/rubyonrails-security/NOjKiGeXUgw\n\u001B[31mTitle: \u001B[0mAbility to forge per-form CSRF tokens given a global CSRF token\n\u001B[31mSolution: upgrade to \u001B[0m~> 5.2.4.3, >= 6.0.3.1\n"
