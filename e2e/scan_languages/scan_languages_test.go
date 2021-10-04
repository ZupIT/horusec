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

// Test e2e refers workflow: .github/workflows/e2e.yml
// In step: e2e-cli
package scan_languages

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get current working directory: %v\n", err)
		os.Exit(1)
	}
	bin := path.Join(wd, "tmp-horusec")

	cmd := exec.Command("go", "build", fmt.Sprintf("-o=%s", bin), path.Join(wd, "..", "..", "cmd", "app"))
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "GOOS=linux")
	cmd.Env = append(cmd.Env, "GOARCH=amd64")

	defer func() {
		if err := os.Remove(bin); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove binary file: %v\n", err)
		}
	}()

	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintln(os.Stderr, string(output))
		fmt.Fprintf(os.Stderr, "Failed to compile horusec: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func TestHorusecCLI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	testcases := []struct {
		name          string
		target        string
		vulnerabilies int
	}{
		{
			name:          "Leaks",
			target:        filepath.Join("leaks", "example1"),
			vulnerabilies: 25,
		},
		{
			name:          "Go",
			target:        filepath.Join("go", "example1"),
			vulnerabilies: 19,
		},
		{
			name:          "Csharp",
			target:        filepath.Join("csharp", "example1"),
			vulnerabilies: 13,
		},
		{
			name:          "Ruby",
			target:        filepath.Join("ruby", "example1"),
			vulnerabilies: 54,
		},
		{
			name:          "PythonBandit",
			target:        filepath.Join("python", "example1"),
			vulnerabilies: 6,
		},
		{
			name:          "PythonSafety",
			target:        filepath.Join("python", "example2"),
			vulnerabilies: 20,
		},
		{
			name:          "Java",
			target:        filepath.Join("java", "example1"),
			vulnerabilies: 1,
		},
		{
			name:          "Kotlin",
			target:        filepath.Join("kotlin", "example1"),
			vulnerabilies: 1,
		},
		{
			name:          "JavascriptNPM",
			target:        filepath.Join("javascript", "example1"),
			vulnerabilies: 31,
		},
		{
			name:          "JavascriptYarn",
			target:        filepath.Join("javascript", "example2"),
			vulnerabilies: 28,
		},
		{
			name:          "HCL",
			target:        filepath.Join("hcl", "example1"),
			vulnerabilies: 7,
		},
		{
			name:          "Dart",
			target:        filepath.Join("dart", "example1"),
			vulnerabilies: 3,
		},
		{
			name:          "PHP",
			target:        filepath.Join("php", "example1"),
			vulnerabilies: 12,
		},
		{
			name:          "Yaml",
			target:        filepath.Join("yaml", "example1"),
			vulnerabilies: 1,
		},
		{
			name:          "Elixir",
			target:        filepath.Join("elixir", "example1"),
			vulnerabilies: 3,
		},
		{
			name:          "Nginx",
			target:        filepath.Join("nginx", "example1"),
			vulnerabilies: 4,
		},
		{
			name:          "Swift",
			target:        filepath.Join("swift", "example1"),
			vulnerabilies: 17,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			outFile := execCLI(t, tt.target)
			entity := parseOutputFile(t, outFile)
			assert.Equal(
				t, tt.vulnerabilies, len(entity.AnalysisVulnerabilities),
				"Vulnerabilities in %s is not expected", tt.name,
			)
		})
	}
}

func execCLI(t *testing.T, target string) string {
	wd, err := os.Getwd()
	require.Nil(t, err, "Expected nil error to get current working directory: %v", err)

	bin := path.Join(wd, "tmp-horusec")
	output := path.Join(os.TempDir(), fmt.Sprintf("horusec-analysis-%s.json", uuid.New().String()))
	srcPath := path.Join(wd, "..", "..", "examples", target)

	flags := map[string]string{
		"-p": srcPath,
		"-o": "json",
		"-O": output,
	}
	cmdArguments := []string{
		"start",
	}
	for flag, value := range flags {
		cmdArguments = append(cmdArguments, fmt.Sprintf("%s=%s", flag, value))
	}
	if output, err := exec.Command(bin, cmdArguments...).CombinedOutput(); err != nil {
		cmd := fmt.Sprintf("%s %s", bin, strings.Join(cmdArguments, " "))
		fmt.Fprintln(os.Stderr, string(output))
		t.Fatalf("Error on run command %s: %v\n", cmd, err)
	}

	return output
}

func parseOutputFile(t *testing.T, file string) analysis.Analysis {
	fileContent, err := os.ReadFile(file)
	require.Nil(t, err, "Error on read file to check vulnerabilities", err)

	var horusecAnalysis analysis.Analysis
	err = json.Unmarshal(fileContent, &horusecAnalysis)
	require.Nil(t, err, "Unexpected error to unmarshal file content to analysis.Analysis: %v", err)

	return horusecAnalysis
}
