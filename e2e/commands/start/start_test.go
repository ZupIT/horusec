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

package start_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"

	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/ZupIT/horusec-devkit/pkg/enums/vulnerability"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger/enums"
	"github.com/ZupIT/horusec/internal/enums/outputtype"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

var _ = Describe("running binary Horusec with start parameter", func() {
	var (
		session     *gexec.Session
		flags       map[string]string
		projectPath = testutil.GoExample2
	)

	JustBeforeEach(func() {
		var err error
		flags[testutil.StartFlagDisableDocker] = "true"
		cmd := testutil.GinkgoGetHorusecCmdWithFlags(testutil.CmdStart, flags)
		session, err = gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
		Expect(err).NotTo(HaveOccurred())
		session.Wait(testutil.AverageTimeoutAnalyzeForExamplesFolder)

		if _, hasReturnErrorFlag := flags[testutil.StartFlagReturnError]; hasReturnErrorFlag {
			Expect(session).Should(gexec.Exit(1))
		} else {
			Expect(session).Should(gexec.Exit(0))
		}
	})

	When("global flag --log-level is passed", func() {
		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath: projectPath,
				testutil.GlobalFlagLogLevel:   enums.TraceLevel.String(),
			}
		})

		It("Checks if the log level was set as trace", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(`\"log_level\": \"trace\"`))
		})
	})

	When("global flag --config-file-path is passed", func() {
		configFilePathToTest := filepath.Join(projectPath, "horusec-config.json")

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:     projectPath,
				testutil.GlobalFlagConfigFilePath: configFilePathToTest,
				testutil.GlobalFlagLogLevel:       enums.TraceLevel.String(),
			}
		})

		It("Checks if the config file path was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"config_file_path\": \"%s\"`, testutil.NormalizePathToAssertInJSON(configFilePathToTest))))
		})
	})

	When("global flag --log-file-path is passed", func() {
		logFilePathToTest := filepath.Join(os.TempDir(), fmt.Sprintf("%s-test.txt", uuid.New()))

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:  projectPath,
				testutil.GlobalFlagLogFilePath: logFilePathToTest,
			}
		})

		It("Checks if the log file path was set and file is created", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`Set log file to %s`, testutil.NormalizePathToAssert(logFilePathToTest))))
			Expect(logFilePathToTest).Should(BeAnExistingFile())
		})
	})

	When("--project-path is passed", func() {
		It("Checks if the project path property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"project_path\": \"%s\"`, testutil.NormalizePathToAssertInJSON(projectPath))))
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`Project sent to folder in location: [%s`, testutil.NormalizePathToAssert(projectPath))))
		})
	})

	When("--disable-docker is passed", func() {
		It("Checks if the disable docker was set as true", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(`\"disable_docker\": true`))
		})
	})

	When("--analysis-timeout is passed", func() {
		analysisTimeout := "500"

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:     projectPath,
				testutil.StartFlagAnalysisTimeout: analysisTimeout,
			}
		})

		It("Checks if the timeout property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf("Horusec will return a timeout after %s seconds.", analysisTimeout)))
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"timeout_in_seconds_analysis\": %s`, analysisTimeout)))
		})
	})

	When("--authorization is passed", func() {
		repoAuthorization := uuid.New().String()

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:   projectPath,
				testutil.StartFlagAuthorization: repoAuthorization,
			}
		})

		It("Checks if the repository authorization property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"repository_authorization\": \"%s\"`, testutil.NormalizePathToAssertInJSON(repoAuthorization))))
		})
	})

	When("--certificate-path is passed", func() {
		var certificateFileWithPath string

		BeforeEach(func() {

			certificateFileWithPath = testutil.GinkgoCreateTmpFile("*.crt")

			flags = map[string]string{
				testutil.StartFlagProjectPath:     projectPath,
				testutil.StartFlagCertificatePath: certificateFileWithPath,
			}
		})

		It("Checks if the cert path property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"cert_path\": \"%s\"`, testutil.NormalizePathToAssertInJSON(certificateFileWithPath))))
		})
	})

	When("--output-format and --json-output-file is passed as JSON", func() {
		jsonOutputPath := filepath.Join(os.TempDir(), fmt.Sprintf("%s-e2e-output.json", uuid.New()))

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:        projectPath,
				testutil.StartFlagOutputFormat:       outputtype.JSON,
				testutil.StartFlagJSONOutputFilePath: jsonOutputPath,
			}
		})

		It("Checks if format was set as JSON and the file is created", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"print_output_type\": \"%s\"`, outputtype.JSON)))
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"json_output_file_path\": \"%s\"`, testutil.NormalizePathToAssertInJSON(jsonOutputPath))))
			Expect(jsonOutputPath).Should(BeAnExistingFile())
		})
	})

	When("--output-format and --json-output-file is passed as Text", func() {
		textOutputPath := filepath.Join(os.TempDir(), fmt.Sprintf("%s-e2e-output.txt", uuid.New()))

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:        projectPath,
				testutil.StartFlagOutputFormat:       outputtype.Text,
				testutil.StartFlagJSONOutputFilePath: textOutputPath,
			}
		})

		It("Checks if format was set as text and the file is created", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"print_output_type\": \"%s\"`, outputtype.Text)))
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"json_output_file_path\": \"%s\"`, testutil.NormalizePathToAssertInJSON(textOutputPath))))
			Expect(textOutputPath).Should(BeAnExistingFile())
		})
	})

	When("--output-format is passed as sonarqube with --json-output-file as JSON", func() {
		sonarqubeOutputPath := filepath.Join(os.TempDir(), fmt.Sprintf("%s-e2e-output-sonarqube.json", uuid.New()))

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:        projectPath,
				testutil.StartFlagOutputFormat:       outputtype.SonarQube,
				testutil.StartFlagJSONOutputFilePath: sonarqubeOutputPath,
			}
		})

		It("Checks if format was set as sonarqube and the JSON file is created", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"print_output_type\": \"%s\"`, outputtype.SonarQube)))
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"json_output_file_path\": \"%s\"`, testutil.NormalizePathToAssertInJSON(sonarqubeOutputPath))))
			Expect(sonarqubeOutputPath).Should(BeAnExistingFile())
		})
	})

	When("--request-timeout is passed", func() {
		requestTimeout := "500"

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:    projectPath,
				testutil.StartFlagRequestTimeout: requestTimeout,
			}
		})

		It("Checks if the request timeout property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"timeout_in_seconds_request\": %s`, requestTimeout)))
		})
	})

	When("--return-error is passed", func() {
		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath: projectPath,
				testutil.StartFlagReturnError: "true",
			}
		})

		It("Checks if the return error property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(`"return_error_if_found_vulnerability\": true`))
			Expect(session.ExitCode()).Should(Equal(1))
		})
	})

	When("--risk-accepted is passed", func() {
		riskAcceptedHash := "8d75739ff88edd7acd60321ae6c7ea9f211048f6fdedb426eb58556ad4d87ea4"

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:   testutil.JavaScriptExample4,
				testutil.StartFlagRiskAccept:    riskAcceptedHash,
				testutil.StartFlagDisableDocker: "true",
			}
		})

		It("Checks if the risk accepted property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`"risk_accept_hashes\": [\n    \"%s\"\n  ]`, riskAcceptedHash)))
			Expect(session.Out.Contents()).To(ContainSubstring("YOUR ANALYSIS HAD FINISHED WITHOUT ANY VULNERABILITY!"))
		})
	})

	When("--false-positive is passed", func() {
		falsePositiveHash := "8d75739ff88edd7acd60321ae6c7ea9f211048f6fdedb426eb58556ad4d87ea4"

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:   testutil.JavaScriptExample4,
				testutil.StartFlagFalsePositive: falsePositiveHash,
				testutil.StartFlagDisableDocker: "true",
			}
		})

		It("Checks if the risk accepted property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`"false_positive_hashes\": [\n    \"%s\"\n  ]`, falsePositiveHash)))
			Expect(session.Out.Contents()).To(ContainSubstring("YOUR ANALYSIS HAD FINISHED WITHOUT ANY VULNERABILITY!"))
		})
	})

	When("--repository-name is passed", func() {
		repositoryName := "horusec-e2e-test"

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:    projectPath,
				testutil.StartFlagRepositoryName: repositoryName,
			}
		})

		It("Checks if the repository name property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"repository_name\": \"%s\"`, repositoryName)))
		})

		When("--enable-commit-author is passed", func() {
			BeforeEach(func() {
				flags = map[string]string{
					testutil.StartFlagProjectPath:        projectPath,
					testutil.StartFlagEnableCommitAuthor: "true",
				}
			})

			It("Checks if the enable commit author property was set", func() {
				Expect(session.Out.Contents()).To(ContainSubstring(`\"enable_commit_author\": true`))
				Expect(session.Out.Contents()).To(ContainSubstring(`Commit Author:`))
				Expect(session.Out.Contents()).To(ContainSubstring(`Commit Date:`))
				Expect(session.Out.Contents()).To(ContainSubstring(`Commit Email:`))
				Expect(session.Out.Contents()).To(ContainSubstring(`Commit CommitHash:`))
				Expect(session.Out.Contents()).To(ContainSubstring(`Commit Message:`))
			})
		})

		When("--enable-git-history is passed", func() {
			BeforeEach(func() {
				flags = map[string]string{
					testutil.StartFlagProjectPath:      projectPath,
					testutil.StartFlagEnableGitHistory: "true",
				}
			})

			It("Checks if the enable git history property was set", func() {
				Expect(session.Out.Contents()).To(ContainSubstring(`\"enable_git_history_analysis\": true`))
				Expect(session.Out.Contents()).To(ContainSubstring(`Starting the analysis with git history enabled`))
			})
		})
	})

	When("--ignore-severity is passed", func() {
		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:    projectPath,
				testutil.StartFlagIgnoreSeverity: severities.Critical.ToString(),
			}
		})

		It("Checks if the ignore severity property was set and ignore all vulnerabilities.", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`"severities_to_ignore\": [\n    \"%s\"\n  ]`, severities.Critical.ToString())))
			Expect(session.Out.Contents()).To(ContainSubstring("YOUR ANALYSIS HAD FINISHED WITHOUT ANY VULNERABILITY!"))
		})
	})

	When("--monitor-retry-count is passed", func() {
		monitorRetryCount := "50"

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:       projectPath,
				testutil.StartFlagMonitorRetryCount: monitorRetryCount,
			}
		})

		It("Checks if the monitor retry count property was set.", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`"monitor_retry_in_seconds\": %s`, monitorRetryCount)))
		})
	})

	When("--insecure-skip-verify is passed", func() {
		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:        projectPath,
				testutil.StartFlagInsecureSkipVerify: "true",
			}
		})

		It("Checks if the insecure skip verify property was set.", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(`\"cert_insecure_skip_verify\": true`))
		})
	})

	When("--horusec-api and --headers is passed", func() {
		horusecApiUrl := "http://localhost:8005"
		horusecApiHeaderKey := "Authorization"
		horusecApiHeaderValue := "MySuperSecretToken"

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath: projectPath,
				testutil.StartFlagHorusecURL:  horusecApiUrl,
				testutil.StartFlagHeaders:     fmt.Sprintf("%s=%s", horusecApiHeaderKey, horusecApiHeaderValue),
			}
		})

		It("Checks if the horusec api and headers properties was set.", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"horusec_api_uri\": \"%s\"`, horusecApiUrl)))
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"headers\": {\n    \"%s\": \"%s\"\n  }`, horusecApiHeaderKey, horusecApiHeaderValue)))
		})
	})

	When("--ignore is passed", func() {
		patternToIgnore := "**/*.js"
		fileIgnored := filepath.Join(testutil.JavaScriptExample4, "test.js")

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagIgnore:      patternToIgnore,
				testutil.StartFlagProjectPath: testutil.JavaScriptExample4,
			}
		})

		It("Checks if the ignore property was set and ignore all files.", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`"files_or_paths_to_ignore\": [\n    \"%s\"\n  ]`, patternToIgnore)))
			Expect(session.Out.Contents()).To(ContainSubstring("YOUR ANALYSIS HAD FINISHED WITHOUT ANY VULNERABILITY!"))
			Expect(session.Out.Contents()).To(ContainSubstring("When starting the analysis WE SKIP A TOTAL OF 1 FILES that are not considered to be analyzed."))
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf("The file or folder was ignored to send analysis:[%s]", testutil.NormalizePathToAssert(fileIgnored))))
		})
	})

	When("--enable-shellcheck is passed", func() {
		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:      projectPath,
				testutil.StartFlagEnableShellcheck: "true",
			}
		})

		It("Checks if the enable shellcheck property was set.", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(`\"enable_shell_check\": true`))
		})
	})

	When("--information-severity is passed", func() {
		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:         testutil.JavaScriptExample1,
				testutil.StartFlagInformationSeverity: "true",
			}
		})

		It("Checks if the information severity property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(`\"enable_information_severity\": true`))
			Expect(session.Out.Contents()).NotTo(ContainSubstring("Horusec not show info vulnerabilities in this analysis"))
		})
	})

	When("--container-bind-project-path is passed", func() {
		filePathAnalyzed := filepath.Join(os.TempDir(), "test.js")

		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:              testutil.JavaScriptExample4,
				testutil.StartFlagContainerBindProjectPath: os.TempDir(),
			}
		})

		It("Checks if container bind project path property was set.", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf("File: %s", filePathAnalyzed)))
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`\"container_bind_project_path\": \"%s\"`, testutil.NormalizePathToAssertInJSON(os.TempDir()))))
		})
	})

	When("--show-vulnerabilities-types is passed", func() {
		BeforeEach(func() {
			flags = map[string]string{
				testutil.StartFlagProjectPath:              projectPath,
				testutil.StartFlagShowVulnerabilitiesTypes: vulnerability.RiskAccepted.ToString(),
			}
		})

		It("Checks if show vulnerabilities types property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(fmt.Sprintf(`"show_vulnerabilities_types\": [\n    \"%s\"\n  ]`, vulnerability.RiskAccepted.ToString())))
			Expect(session.Out.Contents()).To(ContainSubstring("YOUR ANALYSIS HAD FINISHED WITHOUT ANY VULNERABILITY!"))
		})
	})

	When("--custom-path-rules is passed", func() {
		customRulesJson := testutil.GinkgoCreateTmpFile("*.json")
		writeJsonFile(customRulesJson)

		BeforeEach(func() {

			flags = map[string]string{
				testutil.StartFlagProjectPath:     testutil.JavaExample1,
				testutil.StartFlagCustomRulesPath: customRulesJson,
			}
		})

		It("Checks if the custom rules path property was set", func() {
			Expect(session.Out.Contents()).To(ContainSubstring(`\"custom_rules_path\": \"%s\"`, testutil.NormalizePathToAssertInJSON(customRulesJson)))
			Eventually(session.Wait(testutil.AverageTimeoutAnalyzeForExamplesFolder).Out).Should(gbytes.Say(`Language: Java`))
			Eventually(session.Wait(testutil.AverageTimeoutAnalyzeForExamplesFolder).Out).Should(gbytes.Say(`Severity: LOW`))
			Eventually(session.Wait(testutil.AverageTimeoutAnalyzeForExamplesFolder).Out).Should(gbytes.Say(`Confidence: LOW`))
			Eventually(session.Wait(testutil.AverageTimeoutAnalyzeForExamplesFolder).Out).Should(gbytes.Say(`RuleID: HS-JAVA-99999999999`))
			Eventually(session.Wait(testutil.AverageTimeoutAnalyzeForExamplesFolder).Out).Should(gbytes.Say(`Details: Teste QA`))
			Eventually(session.Wait(testutil.AverageTimeoutAnalyzeForExamplesFolder).Out).Should(gbytes.Say(`Teste de description QA`))
			Eventually(session.Wait(testutil.AverageTimeoutAnalyzeForExamplesFolder).Out).Should(gbytes.Say(`Type: Vulnerability`))

		})
	})
})

func writeJsonFile(path string) {
	file, err := os.OpenFile(path, os.O_RDWR, os.ModePerm)
	if err != nil {
		Fail(fmt.Sprintf("The following error occurred when opening the file: %v", err))
	}

	defer file.Close()

	customRules := []map[string]interface{}{

		{
			"id":          "HS-JAVA-99999999999",
			"name":        "Teste QA",
			"description": "Teste de description QA",
			"language":    "Java",
			"severity":    "LOW",
			"confidence":  "LOW",
			"type":        "Regular",
			"expressions": []string{".*"},
		},
	}

	b, err := json.Marshal(customRules)
	if err != nil {
		Fail(fmt.Sprintf("The following error occurred to marshal json: %v", err))
	}

	if _, err := file.Write(b); err != nil {
		Fail(fmt.Sprintf("The following error occurred when writing to the file: %v", err))
	}
}
