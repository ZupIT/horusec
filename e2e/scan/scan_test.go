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

package scan_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

var _ = Describe("Scan vulnerabilities example folder", func() {
	testcases := []struct {
		name            string
		target          string
		vulnerabilities int
	}{
		{
			name:            "Leaks",
			target:          testutil.LeaksExample1,
			vulnerabilities: 25,
		},
		{
			name:            "Go",
			target:          testutil.GoExample1,
			vulnerabilities: 19,
		},
		{
			name:            "Csharp",
			target:          testutil.CsharpExample1,
			vulnerabilities: 13,
		},
		{
			name:            "Ruby",
			target:          testutil.RubyExample1,
			vulnerabilities: 55,
		},
		{
			name:            "PythonBandit",
			target:          testutil.PythonExample1,
			vulnerabilities: 6,
		},
		{
			name:            "PythonSafety",
			target:          testutil.PythonExample2,
			vulnerabilities: 20,
		},
		{
			name:            "Java",
			target:          testutil.JavaExample1,
			vulnerabilities: 1,
		},
		{
			name:            "Kotlin",
			target:          testutil.KotlinExample1,
			vulnerabilities: 1,
		},
		{
			name:            "JavascriptNPM",
			target:          testutil.JavaScriptExample1,
			vulnerabilities: 29,
		},
		{
			name:            "JavascriptYarn",
			target:          testutil.JavaScriptExample2,
			vulnerabilities: 28,
		},
		{
			name:            "HCL",
			target:          testutil.Hclxample1,
			vulnerabilities: 7,
		},
		{
			name:            "Dart",
			target:          testutil.DartExample1,
			vulnerabilities: 3,
		},
		{
			name:            "PHP",
			target:          testutil.PHPExample1,
			vulnerabilities: 12,
		},
		{
			name:            "Yaml",
			target:          testutil.YamlExample1,
			vulnerabilities: 1,
		},
		{
			name:            "Elixir",
			target:          testutil.ElixirExample1,
			vulnerabilities: 3,
		},
		{
			name:            "Nginx",
			target:          testutil.NginxExample1,
			vulnerabilities: 4,
		},
		{
			name:            "Swift",
			target:          testutil.SwiftExample1,
			vulnerabilities: 17,
		},
	}

	for _, tt := range testcases {
		It(tt.name, func() {
			bin := testutil.GomegaBuildHorusecBinary()
			output := path.Join(os.TempDir(), fmt.Sprintf("horusec-analysis-%s.json", uuid.New().String()))

			flags := map[string]string{
				"-p": tt.target,
				"-o": "json",
				"-O": output,
			}

			cmdArguments := []string{
				"start",
			}

			for flag, value := range flags {
				cmdArguments = append(cmdArguments, fmt.Sprintf("%s=%s", flag, value))
			}

			cmd := exec.Command(bin, cmdArguments...)
			err := cmd.Run()

			stdout := bytes.NewBufferString("")
			stderr := bytes.NewBufferString("")

			cmd.Stdout = stdout
			cmd.Stderr = stderr

			if err != nil {
				Fail(fmt.Sprintf("Error on run CLI to scan tests %v\nstderr: %s\n\nstdout: %s\n", err,
					stderr.String(), stdout.String()))
			}

			fileContent, err := os.ReadFile(output)

			if err != nil {
				Fail(fmt.Sprintf("Error on read file for scan on e2e test %v", err))
			}

			var horusecAnalysis analysis.Analysis
			err = json.Unmarshal(fileContent, &horusecAnalysis)

			if err != nil {
				Fail(fmt.Sprintf("Error on read json result for horusec scan example folder %v", err))
			}

			Expect(tt.vulnerabilities).Should(Equal(len(horusecAnalysis.AnalysisVulnerabilities)))
		})
	}
})
