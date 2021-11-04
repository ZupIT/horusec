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

package analysis_test

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

type AnalysisTestCase struct {
	Language       languages.Language
	AnalysisFolder string
	ExpectedTools  []tools.Tool
}

func (A AnalysisTestCase) RunAnalysisTestCase() (*gexec.Session, error) {
	flags := map[string]string{
		testutil.StartFlagProjectPath: A.AnalysisFolder,
	}
	cmd := testutil.GinkgoGetHorusecCmdWithFlags(testutil.CmdStart, flags)
	return gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
}

var testcases = []AnalysisTestCase{
	{
		Language:       languages.Python,
		AnalysisFolder: testutil.PythonExample1,
		ExpectedTools:  []tools.Tool{tools.Bandit, tools.BundlerAudit, tools.Trivy},
	},
	{
		Language:       languages.Ruby,
		AnalysisFolder: testutil.RubyExample1,
		ExpectedTools:  []tools.Tool{tools.Brakeman, tools.BundlerAudit, tools.Trivy},
	},
	{
		Language:       languages.Javascript,
		AnalysisFolder: testutil.JavaScriptExample1,
		ExpectedTools:  []tools.Tool{tools.NpmAudit, tools.YarnAudit, tools.HorusecEngine, tools.Semgrep, tools.Trivy},
	},
	{
		Language:       languages.Go,
		AnalysisFolder: testutil.GoExample1,
		ExpectedTools:  []tools.Tool{tools.GoSec, tools.Semgrep, tools.Nancy, tools.Trivy},
	},
	{
		Language:       languages.CSharp,
		AnalysisFolder: testutil.CsharpExample1,
		ExpectedTools:  []tools.Tool{tools.SecurityCodeScan, tools.HorusecEngine, tools.DotnetCli, tools.Trivy},
	},
	{
		Language:       languages.Java,
		AnalysisFolder: testutil.JavaExample1,
		ExpectedTools:  []tools.Tool{tools.HorusecEngine, tools.Semgrep, tools.Trivy},
	},
	{
		Language:       languages.Kotlin,
		AnalysisFolder: testutil.KotlinExample1,
		ExpectedTools:  []tools.Tool{tools.HorusecEngine},
	},
	{
		Language:       languages.Leaks,
		AnalysisFolder: testutil.LeaksExample1,
		ExpectedTools:  []tools.Tool{tools.GitLeaks, tools.HorusecEngine},
	},
	{
		Language:       languages.PHP,
		AnalysisFolder: testutil.PHPExample1,
		ExpectedTools:  []tools.Tool{tools.Semgrep, tools.PhpCS, tools.Trivy},
	},
	{
		Language:       languages.Dart,
		AnalysisFolder: testutil.DartExample1,
		ExpectedTools:  []tools.Tool{tools.HorusecEngine},
	},
	{
		Language:       languages.Elixir,
		AnalysisFolder: testutil.ElixirExample1,
		ExpectedTools:  []tools.Tool{tools.MixAudit, tools.Sobelow},
	},
	{
		Language:       languages.Nginx,
		AnalysisFolder: testutil.NginxExample1,
		ExpectedTools:  []tools.Tool{tools.HorusecEngine},
	},
	{
		Language:       languages.Swift,
		AnalysisFolder: testutil.SwiftExample1,
		ExpectedTools:  []tools.Tool{tools.HorusecEngine},
	},
}

var _ = Describe("Run a complete horusec analysis", func() {
	var (
		session *gexec.Session
	)

	for _, tt := range testcases {
		Describe(fmt.Sprintf("Running on %s codebase.", tt.Language.ToString()), func() {
			session, _ = tt.RunAnalysisTestCase()
			session.Wait(2 * time.Minute)

			It("execute command without error", func() {
				Expect(session.ExitCode()).To(Equal(0))
			})

			It("vulnerabilities were found", func() {
				Expect(session.Out.Contents()).To(ContainSubstring("{HORUSEC_CLI} Vulnerability Hash expected to be FIXED"))
				Expect(session.Out.Contents()).To(ContainSubstring("VULNERABILITIES WERE FOUND IN YOUR CODE"))
			})

			It("running all expected tools", func() {
				for _, tool := range tt.ExpectedTools {
					Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf("{HORUSEC_CLI} Running %s", tool.ToString())))
				}
			})
		})
	}
})
