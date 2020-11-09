// Test e2e refers workflow: .github/workflows/e2e.yml
// In step: e2e-cli
package scan_languages

import (
	"encoding/json"
	"fmt"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/zip"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestMain(m *testing.M) {
	_ = os.RemoveAll("./analysis")
	_ = os.RemoveAll("./tmp")
	code := m.Run()
	_ = os.RemoveAll("./analysis")
	_ = os.RemoveAll("./tmp")
	os.Exit(code)
}

func TestHorusecCLILanguages(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	var wg sync.WaitGroup
	go RunGolangTest(t, &wg)
	go RunNetCoreTest(t, &wg)
	go RunRubyTest(t, &wg)
	go RunPythonBanditTest(t, &wg)
	go RunPythonSafetyTest(t, &wg)
	go RunJavaTest(t, &wg)
	go RunKotlinTest(t, &wg)
	go RunJavascriptNpmTest(t, &wg)
	go RunJavascriptYarnTest(t, &wg)
	go RunGitTest(t, &wg)
	go RunHclTest(t, &wg)
	wg.Add(11)
	wg.Wait()
}

func RunGitTest(t *testing.T, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "gitleaks")
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.GreaterOrEqual(t, len(analysis.AnalysisVulnerabilities), 1, "Vulnerabilities in leaks is not expected")
}

func RunPythonBanditTest(t *testing.T, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "python-bandit")
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.GreaterOrEqual(t, len(analysis.AnalysisVulnerabilities), 1, "Vulnerabilities in python-bandit is not expected")
}

func RunPythonSafetyTest(t *testing.T, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "python-safety")
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.GreaterOrEqual(t, len(analysis.AnalysisVulnerabilities), 1, "Vulnerabilities in python-safety is not expected")
}

func RunJavascriptNpmTest(t *testing.T, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "javascript-npm")
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.GreaterOrEqual(t, len(analysis.AnalysisVulnerabilities), 1, "Vulnerabilities in javascript-npm is not expected")

}

func RunJavascriptYarnTest(t *testing.T, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "javascript-yarn")
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.GreaterOrEqual(t, len(analysis.AnalysisVulnerabilities), 1, "Vulnerabilities in javascript-yarn is not expected")
}

func RunKotlinTest(t *testing.T, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "kotlin-spotbug")
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.GreaterOrEqual(t, len(analysis.AnalysisVulnerabilities), 1, "Vulnerabilities in kotlin is not expected")
}

func RunNetCoreTest(t *testing.T, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "netcore3-1")
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.GreaterOrEqual(t, len(analysis.AnalysisVulnerabilities), 1, "Vulnerabilities in netcore is not expected")
}

func RunRubyTest(t *testing.T, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "ruby-brakeman")
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.GreaterOrEqual(t, len(analysis.AnalysisVulnerabilities), 1, "Vulnerabilities in ruby is not expected")
}

func RunJavaTest(t *testing.T, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "java-spotbug")
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.GreaterOrEqual(t, len(analysis.AnalysisVulnerabilities), 1, "Vulnerabilities in java is not expected")
}

func RunGolangTest(t *testing.T, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "go-gosec")
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.GreaterOrEqual(t, len(analysis.AnalysisVulnerabilities), 1, "Vulnerabilities in golang is not expected")
}

func RunHclTest(t *testing.T, s *sync.WaitGroup) {
	defer s.Done()
	fileOutput := runHorusecCLIUsingZip(t, "hcl-tfsec")
	analysis := extractVulnerabilitiesFromOutput(fileOutput)
	assert.GreaterOrEqual(t, len(analysis.AnalysisVulnerabilities), 1, "Vulnerabilities in hcl is not expected")
}

func runHorusecCLIUsingZip(t *testing.T, zipName string, othersFlags ...map[string]string) string {
	assert.NoError(t, os.MkdirAll("./tmp", 0750))
	fakeAnalysisID := uuid.New().String()
	fileOutput := fmt.Sprintf("./tmp/horusec-analysis-%s.json", fakeAnalysisID)
	destPath := "analysis/" + fakeAnalysisID
	destPath, err := filepath.Abs(destPath)
	assert.NoError(t, err)
	srcPath := "../../../development-kit/pkg/utils/test/zips/" + zipName + "/" + zipName + ".zip"
	assert.NoError(t, zip.NewZip().UnZip(srcPath, destPath))
	flags := map[string]string{
		"-p": strings.TrimSpace(destPath),
		"-o": strings.TrimSpace("json"),
		"-O": strings.TrimSpace(fileOutput),
	}
	for _, otherFlag := range othersFlags {
		for flag, value := range otherFlag {
			flags[flag] = value
		}
	}
	cmdArguments := []string{
		"run",
		"../../../horusec-cli/cmd/horusec/main.go",
		"start",
	}
	for flag, value := range flags {
		cmdArguments = append(cmdArguments, fmt.Sprintf("%s=%s", flag, value))
	}
	logger.LogInfo(fmt.Sprintf("Running command: go %s", strings.Join(cmdArguments, " ")))
	cmd := exec.Command("go", cmdArguments...)
	_ = cmd.Run()

	return fileOutput
}

func extractVulnerabilitiesFromOutput(fileOutput string) horusec.Analysis {
	fileContent, err := ioutil.ReadFile(fileOutput)
	logger.LogError("Error on read file to check vulnerabilities", err)
	horusecAnalysis := horusec.Analysis{}
	logger.LogError("Error on unmarshal fileContent to horusecAnalysis", json.Unmarshal(fileContent, &horusecAnalysis))
	return horusecAnalysis
}
