// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package analysis

import (
	"fmt"
	"runtime"

	"github.com/ZupIT/horusec-devkit/pkg/enums/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	. "github.com/onsi/ginkgo"
	"github.com/onsi/gomega/gexec"

	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

// Expected struct represents the validations that will be expected when comparing the final results of the analysis
type Expected struct {
	Language           languages.Language
	OutputsContains    []string
	OutputsNotContains []string
	ExitCode           int
}

// Command struct represents all content for run command and your result who: output and exit code
type Command struct {
	Flags    map[string]string
	Output   string
	ExitCode int
}

// TestCase struct represents group of content for validate the test e2e of the tool and if is necessary docker for run this tool or not
type TestCase struct {
	Tool           tools.Tool
	RequiredDocker bool
	Command        Command
	Expected       Expected
}

func (tc TestCase) RunAnalysisTestCase() (*gexec.Session, error) {
	isWindows := runtime.GOOS == "windows"
	if isWindows || !tc.RequiredDocker {
		tc.Command.Flags[testutil.StartFlagDisableDocker] = "true"
	}
	cmd := testutil.GinkgoGetHorusecCmdWithFlags(testutil.CmdStart, tc.Command.Flags)
	return gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
}

func NewTestCase() []*TestCase {
	return []*TestCase{
		{
			Tool:           tools.HorusecEngine,
			RequiredDocker: false,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath: testutil.ExamplesPath,
				},
			},
			Expected: Expected{
				Language: languages.Generic,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					"In this analysis, a total of 73 possible vulnerabilities were found and we classified them into:",
					"Total of Vulnerability CRITICAL is: 22",
					"Total of Vulnerability HIGH is: 24",
					"Total of Vulnerability MEDIUM is: 24",
					"Total of Vulnerability LOW is: 3",
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.CSharp),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Dart),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Java),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Javascript),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Kotlin),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Nginx),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Swift),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Yaml),
					fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.GoSec),
					fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.SecurityCodeScan),
					fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.Brakeman),
					fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.Safety),
					fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.Bandit),
					fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.NpmAudit),
					fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.YarnAudit),
					// TODO: This log show only if pass --enable-git-history, we can see if this tool was runned or not without this flag
					// fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.GitLeaks),
					fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.TfSec),
					fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.Checkov),
					fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.Semgrep),
					fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.Flawfinder),
					fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.PhpCS),
					fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.MixAudit),
					fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.Sobelow),
					// TODO: This log show only if pass --enable-shellcheck, we can see if this tool was runned or not without this flag
					// fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.ShellCheck),
					fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.BundlerAudit),
					// TODO: This log show only if pass --enable-owasp-dependency-check, we can see if this tool was runned or not without this flag
					// fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.OwaspDependencyCheck),
					fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.DotnetCli),
					fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.Nancy),
					fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.Trivy),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} The tool was ignored for run in this analysis: %s", tools.HorusecEngine),
				},
			},
		},
		{
			Tool:           tools.Bandit,
			RequiredDocker: true,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath: testutil.PythonExample2,
				},
			},
			Expected: Expected{
				Language: languages.Python,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.Bandit, languages.Python),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.Bandit, languages.Python),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.Safety, languages.Python),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.Safety, languages.Python),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.Semgrep, languages.Generic),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.Semgrep, languages.Generic),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.Trivy, languages.Generic),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.Trivy, languages.Generic),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.HorusecEngine, languages.Leaks),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} Something error went wrong in %s tool", tools.Bandit),
				},
			},
		},
		{
			Tool:           tools.Safety,
			RequiredDocker: true,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath: testutil.PythonExample2,
				},
			},
			Expected: Expected{
				Language: languages.Python,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.Bandit, languages.Python),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.Bandit, languages.Python),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.Safety, languages.Python),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.Safety, languages.Python),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.Semgrep, languages.Generic),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.Semgrep, languages.Generic),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.Trivy, languages.Generic),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.Trivy, languages.Generic),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.HorusecEngine, languages.Leaks),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} Something error went wrong in %s tool", tools.Safety),
				},
			},
		},
		{
			Tool:           tools.GoSec,
			RequiredDocker: true,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath: testutil.GoExample1,
				},
			},
			Expected: Expected{
				Language: languages.Go,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.GoSec, languages.Go),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.GoSec, languages.Go),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.HorusecEngine, languages.Leaks),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} Something error went wrong in %s tool", tools.GoSec),
				},
			},
		},
		{
			Tool:           tools.SecurityCodeScan,
			RequiredDocker: true,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath: testutil.CsharpExample1,
				},
			},
			Expected: Expected{
				Language: languages.CSharp,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.SecurityCodeScan, languages.CSharp),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.SecurityCodeScan, languages.CSharp),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.HorusecEngine, languages.Leaks),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} Something error went wrong in %s tool", tools.SecurityCodeScan),
				},
			},
		},
		{
			Tool:           tools.NpmAudit,
			RequiredDocker: true,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath: testutil.JavaScriptExample1,
				},
			},
			Expected: Expected{
				Language: languages.Javascript,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.NpmAudit, languages.Javascript),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.NpmAudit, languages.Javascript),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.HorusecEngine, languages.Leaks),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} Something error went wrong in %s tool", tools.NpmAudit),
				},
			},
		},
		{
			Tool:           tools.YarnAudit,
			RequiredDocker: true,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath: testutil.JavaScriptExample2,
				},
			},
			Expected: Expected{
				Language: languages.Javascript,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.YarnAudit, languages.Javascript),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.YarnAudit, languages.Javascript),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.HorusecEngine, languages.Leaks),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} Something error went wrong in %s tool", tools.YarnAudit),
				},
			},
		},
		{
			Tool:           tools.TfSec,
			RequiredDocker: true,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath: testutil.Hclxample1,
				},
			},
			Expected: Expected{
				Language: languages.HCL,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.TfSec, languages.HCL),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.TfSec, languages.HCL),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.HorusecEngine, languages.Leaks),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} Something error went wrong in %s tool", tools.TfSec),
				},
			},
		},
		{
			Tool:           tools.Checkov,
			RequiredDocker: true,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath: testutil.Hclxample1,
				},
			},
			Expected: Expected{
				Language: languages.HCL,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.Checkov, languages.HCL),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.Checkov, languages.HCL),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.HorusecEngine, languages.Leaks),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} Something error went wrong in %s tool", tools.Checkov),
				},
			},
		},
		{
			Tool:           tools.Flawfinder,
			RequiredDocker: true,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath: testutil.CExample1,
				},
			},
			Expected: Expected{
				Language: languages.C,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.Flawfinder, languages.C),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.Flawfinder, languages.C),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.HorusecEngine, languages.Leaks),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} Something error went wrong in %s tool", tools.Flawfinder),
				},
			},
		},
		{
			Tool:           tools.PhpCS,
			RequiredDocker: true,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath: testutil.PHPExample1,
				},
			},
			Expected: Expected{
				Language: languages.PHP,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.PhpCS, languages.PHP),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.PhpCS, languages.PHP),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.HorusecEngine, languages.Leaks),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} Something error went wrong in %s tool", tools.PhpCS),
				},
			},
		},
		{
			Tool:           tools.MixAudit,
			RequiredDocker: true,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath: testutil.ElixirExample1,
				},
			},
			Expected: Expected{
				Language: languages.Elixir,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.MixAudit, languages.Elixir),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.MixAudit, languages.Elixir),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.HorusecEngine, languages.Leaks),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} Something error went wrong in %s tool", tools.MixAudit),
				},
			},
		},
		{
			Tool:           tools.Sobelow,
			RequiredDocker: true,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath: testutil.ElixirExample1,
				},
			},
			Expected: Expected{
				Language: languages.Elixir,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.Sobelow, languages.Elixir),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.Sobelow, languages.Elixir),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.HorusecEngine, languages.Leaks),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} Something error went wrong in %s tool", tools.Sobelow),
				},
			},
		},
		{
			Tool:           tools.Brakeman,
			RequiredDocker: true,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath: testutil.RubyExample1,
					testutil.StartFlagIgnore:      "**/*.js, **/*.html, **/*.py, **/*.ts",
				},
			},
			Expected: Expected{
				Language: languages.Ruby,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.Brakeman, languages.Ruby),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.Brakeman, languages.Ruby),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.HorusecEngine, languages.Leaks),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} Something error went wrong in %s tool", tools.Brakeman),
				},
			},
		},
		{
			Tool:           tools.BundlerAudit,
			RequiredDocker: true,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath: testutil.RubyExample1,
					testutil.StartFlagIgnore:      "**/*.js, **/*.html, **/*.py, **/*.ts",
				},
			},
			Expected: Expected{
				Language: languages.Ruby,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.BundlerAudit, languages.Ruby),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.BundlerAudit, languages.Ruby),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.HorusecEngine, languages.Leaks),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} Something error went wrong in %s tool", tools.BundlerAudit),
				},
			},
		},
		{
			Tool:           tools.DotnetCli,
			RequiredDocker: true,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath: testutil.CsharpExample1,
				},
			},
			Expected: Expected{
				Language: languages.CSharp,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.DotnetCli, languages.CSharp),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.DotnetCli, languages.CSharp),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.HorusecEngine, languages.Leaks),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} Something error went wrong in %s tool", tools.DotnetCli),
				},
			},
		},
		{
			Tool:           tools.Nancy,
			RequiredDocker: true,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath: testutil.GoExample1,
				},
			},
			Expected: Expected{
				Language: languages.Go,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.Nancy, languages.Go),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.Nancy, languages.Go),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.HorusecEngine, languages.Leaks),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} Something error went wrong in %s tool", tools.Nancy),
				},
			},
		},
		{
			Tool:           tools.ShellCheck,
			RequiredDocker: true,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath:      testutil.LeaksExample1,
					testutil.StartFlagEnableShellcheck: "true",
				},
			},
			Expected: Expected{
				Language: languages.Shell,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.ShellCheck, languages.Shell),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.ShellCheck, languages.Shell),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.HorusecEngine, languages.Leaks),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} Something error went wrong in %s tool", tools.ShellCheck),
				},
			},
		},
		{
			Tool:           tools.Semgrep,
			RequiredDocker: true,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath: testutil.GoExample1,
				},
			},
			Expected: Expected{
				Language: languages.Generic,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.Semgrep, languages.Generic),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.Semgrep, languages.Generic),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.HorusecEngine, languages.Leaks),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} Something error went wrong in %s tool", tools.Semgrep),
				},
			},
		},
		{
			Tool:           tools.Trivy,
			RequiredDocker: true,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath: testutil.LeaksExample1,
				},
			},
			Expected: Expected{
				Language: languages.Generic,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.Trivy, languages.Generic),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.Trivy, languages.Generic),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.HorusecEngine, languages.Leaks),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} Something error went wrong in %s tool", tools.Trivy),
				},
			},
		},
		{
			Tool:           tools.OwaspDependencyCheck,
			RequiredDocker: true,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath:                testutil.JavaScriptExample1,
					testutil.StartFlagEnableOwaspDependencyCheck: "true",
					testutil.StartFlagAnalysisTimeout:            "10000",
				},
			},
			Expected: Expected{
				Language: languages.Generic,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.OwaspDependencyCheck, languages.Generic),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.OwaspDependencyCheck, languages.Generic),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.HorusecEngine, languages.Leaks),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} Something error went wrong in %s tool", tools.OwaspDependencyCheck),
				},
			},
		},
		{
			Tool:           tools.GitLeaks,
			RequiredDocker: true,
			Command: Command{
				Flags: map[string]string{
					testutil.StartFlagProjectPath:        testutil.ExamplesPath,
					testutil.StartFlagEnableGitHistory:   "true",
					testutil.StartFlagEnableCommitAuthor: "true",
					testutil.StartFlagAnalysisTimeout:    "10000",
					testutil.StartFlagIgnore:             "**/ruby/**, **/javascript/**, **/python/**, **/go/**",
				},
			},
			Expected: Expected{
				Language: languages.Generic,
				ExitCode: 0,
				OutputsContains: []string{
					fmt.Sprintf(messages.MsgPrintFinishAnalysisWithStatus, analysis.Success),
					messages.MsgDebugVulnHashToFix,
					messages.MsgWarnAnalysisFoundVulns[16:],
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.GitLeaks, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.GitLeaks, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} Running %s - %s", tools.HorusecEngine, languages.Leaks),
					fmt.Sprintf("{HORUSEC_CLI} %s - %s is finished in analysisID:", tools.HorusecEngine, languages.Leaks),
				},
				OutputsNotContains: []string{
					fmt.Sprintf("{HORUSEC_CLI} Something error went wrong in %s tool", tools.GitLeaks),
				},
			},
		},
	}
}
