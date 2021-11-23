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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/e2e/analysis"
	customimages "github.com/ZupIT/horusec/internal/entities/custom_images"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

const (
	isWindows         = runtime.GOOS == "windows"
	isDarwin          = runtime.GOOS == "darwin"
	horusecConfigName = "horusec-config.json"
)

var _ = Describe("Run a complete horusec analysis when build tools locally", func() {
	tmpDir := CreateHorusecConfigAndReturnTMPDirectory()

	Describe("Running e2e tests when build tools locally", func() {
		allTestsCases := analysis.NewTestCase()

		for idx, testCase := range allTestsCases {
			if !isDarwin {
				horusecConfigFilePathBuildLocally := filepath.Join(tmpDir, horusecConfigName)
				RunTestCase(testCase, horusecConfigFilePathBuildLocally, "(build locally)", idx, len(allTestsCases))

				time.Sleep(2 * time.Second)
			}

			horusecConfigFilePathDownloadFromDockerHub := filepath.Join(allTestsCases[idx].Command.Flags[testutil.StartFlagProjectPath], horusecConfigName)
			RunTestCase(testCase, horusecConfigFilePathDownloadFromDockerHub, "(download from dockerhub)", idx, len(allTestsCases))

			time.Sleep(2 * time.Second)
		}
	})

	AfterEach(func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			Fail(fmt.Sprintf("Error on remove tmp folder: %v", err))
		}
	})
})

func RunTestCase(testCase *analysis.TestCase, horusecConfigFilePath, runType string, idx, lenTestCase int) {
	testCase.Command.Flags[testutil.GlobalFlagConfigFilePath] = horusecConfigFilePath
	if isWindows && testCase.RequiredDocker {
		logger.LogInfo("Tool ignored because is required docker: ", runType, testCase.Tool, fmt.Sprintf("[%v/%v]", idx+1, lenTestCase))
		return
	}
	logger.LogInfo("Preparing test for run e2e: ", runType, testCase.Tool, fmt.Sprintf("[%v/%v]", idx+1, lenTestCase))
	session, err := testCase.RunAnalysisTestCase()
	if err != nil {
		Fail(fmt.Sprintf("Error on run analysis Test Case %s: %v", runType, err))
	}
	session.Wait(testutil.AverageTimeoutAnalyzeForExamplesFolder)
	testCase.Command.Output = string(session.Out.Contents())
	testCase.Command.ExitCode = session.ExitCode()

	It(fmt.Sprintf("Execute command without error for %s: %s", runType, testCase.Tool), func() {
		Expect(testCase.Command.ExitCode).Should(Equal(0))
	})

	It(fmt.Sprintf("Validate is outputs expected exists on tool %s: %s", runType, testCase.Tool), func() {
		for _, outputExpected := range testCase.Expected.OutputsContains {
			Expect(testCase.Command.Output).Should(
				ContainSubstring(outputExpected),
				fmt.Sprintf("The output [%s] not exist in output", outputExpected),
				testCase.Command.Output,
			)
		}
	})

	It(fmt.Sprintf("Validate is outputs not expected exists on tool %s: %s", runType, testCase.Tool), func() {
		for _, outputNotExpected := range testCase.Expected.OutputsNotContains {
			Expect(testCase.Command.Output).ShouldNot(
				ContainSubstring(outputNotExpected),
				fmt.Sprintf("The output [%s] exist in output", outputNotExpected),
				testCase.Command.Output,
			)
		}
	})
}

func CreateHorusecConfigAndReturnTMPDirectory() string {
	tmpDir := filepath.Join(os.TempDir(), "horusec-analysis-e2e-"+uuid.NewString())
	horusecConfigPath := filepath.Join(tmpDir, horusecConfigName)

	if err := os.MkdirAll(tmpDir, os.ModePerm); err != nil {
		Fail(fmt.Sprintf("Error on create tmp folder: %v", err))
	}

	horusecConfigFile, err := os.Create(horusecConfigPath)
	if err != nil {
		Fail(fmt.Sprintf("Error on create config file for scan on e2e test %v", err))
	}

	horusecConfig := config.New()

	newCustomImages := customimages.Default()
	for k := range newCustomImages {
		if k == languages.CSharp {
			newCustomImages[k] = strings.ToLower("local-csharp:local")
		} else {
			newCustomImages[k] = strings.ToLower(fmt.Sprintf("local-%s:local", k))
		}
	}

	horusecConfig.CustomImages = newCustomImages
	horusecConfigBytes, err := json.MarshalIndent(horusecConfig.ToMapLowerCase(), "", "  ")
	if err != nil {
		Fail(fmt.Sprintf("Error on marshall horusec-config.json %v", err))
	}

	_, err = horusecConfigFile.Write(horusecConfigBytes)
	if err != nil {
		Fail(fmt.Sprintf("Error on write config file for scan on e2e test %v", err))
	}
	return tmpDir
}
