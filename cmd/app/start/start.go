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

package start

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/spf13/cobra"

	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/config/dist"
	"github.com/ZupIT/horusec/internal/controllers/analyzer"
	"github.com/ZupIT/horusec/internal/controllers/requirements"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	usecases "github.com/ZupIT/horusec/internal/usecases/cli"
	"github.com/ZupIT/horusec/internal/utils/prompt"
)

// Analyzer is the interface that execute the analysis on some directory.
//
// Analyze returns the total of vulnerabilities founded on directory
type Analyzer interface {
	Analyze() (int, error)
}

// Prompt is the interface that interact with use terminal prompt
//
// Ask read from stdin and return the user input
type Prompt interface {
	Ask(label, defaultValue string) (string, error)
}

// Requirements is the interface that validate Horusec dynamic
// requirements to execute analysis
type Requirements interface {
	ValidateDocker() error
	ValidateGit() error
}

type Start struct {
	configs      *config.Config
	analyzer     Analyzer
	prompt       Prompt
	requirements Requirements
}

func NewStartCommand(configs *config.Config) *Start {
	return &Start{
		configs:      configs,
		prompt:       prompt.NewPrompt(),
		requirements: requirements.NewRequirements(),
	}
}

// CreateStartCommand create the cobra command from start command.
//
// Note that here we only declare the flags and their default values
// the function on PersistentPreRunE field is that make the parsing of
// flags.
//
// nolint:funlen,lll
func (s *Start) CreateStartCommand() *cobra.Command {
	startCmd := &cobra.Command{
		Use:               "start",
		Short:             "Start analysis",
		Long:              "Start the Horusec analysis in the current path",
		Example:           "horusec start",
		PersistentPreRunE: s.configs.PersistentPreRun,
		RunE:              s.runE,
	}

	startCmd.PersistentFlags().
		Int64P(
			"monitor-retry-count", "m",
			s.configs.MonitorRetryInSeconds,
			"The number of retries for the monitor",
		)

	startCmd.PersistentFlags().
		StringP(
			"output-format", "o",
			s.configs.PrintOutputType,
			`Output format of analysis ("text"|"json"|"sarif"|"sonarqube"). For json, sarif, and sonarqube --json-output-file is required`,
		)

	startCmd.PersistentFlags().
		StringSliceP(
			"ignore-severity", "s",
			s.configs.SeveritiesToIgnore,
			`The level of vulnerabilities to ignore in the output ("LOW"|"MEDIUM"|"HIGH"). Example: -s="LOW, HIGH"`,
		)

	startCmd.PersistentFlags().
		StringP(
			"json-output-file", "O",
			s.configs.JSONOutputFilePath,
			`Output file to write analysis result. This flag should be used with --output-format`,
		)

	startCmd.PersistentFlags().
		StringSliceP(
			"ignore", "i",
			s.configs.FilesOrPathsToIgnore,
			`Paths to ignore in the analysis. Example: -i="/path/to/ignore, **/*_test.go, **/assets/**"`,
		)

	startCmd.PersistentFlags().
		StringP(
			"horusec-url", "u",
			s.configs.HorusecAPIUri,
			"The Horusec server address to send analysis results",
		)

	startCmd.PersistentFlags().
		Int64P(
			"request-timeout", "r",
			s.configs.TimeoutInSecondsRequest,
			"The timeout threshold for the request to the Horusec server. The minimum time is 10",
		)

	startCmd.PersistentFlags().
		Int64P(
			"analysis-timeout", "t",
			s.configs.TimeoutInSecondsAnalysis,
			"The timeout threshold for the Horusec CLI wait for the analysis to complete. The minimum time is 10",
		)

	startCmd.PersistentFlags().
		StringP(
			"authorization", "a",
			s.configs.RepositoryAuthorization,
			"Authorization token to use on Horusec server. Read more: https://docs.horusec.io/docs/tutorials/how-to-create-an-authorization-token",
		)

	startCmd.PersistentFlags().
		StringToString(
			"headers",
			s.configs.Headers,
			`Custom headers to send on request to Horusec API. Example --headers='{"X-Auth-Service": "value"}'`,
		)

	startCmd.PersistentFlags().
		BoolP(
			"return-error", "e",
			s.configs.ReturnErrorIfFoundVulnerability,
			`Return exit code 1 if found vulnerabilities. Default value is false (exit code 0)`,
		)

	startCmd.PersistentFlags().
		StringP(
			"project-path", "p",
			s.configs.ProjectPath,
			"Path to run an analysis. If this value is not passed, Horusec will ask if you want to run the analysis in the current directory",
		)

	startCmd.PersistentFlags().
		Bool(
			"enable-git-history",
			s.configs.EnableGitHistoryAnalysis,
			`Run Gitleaks and search for vulnerabilities in all git history of the project https://github.com/zricethezav/gitleaks`,
		)

	startCmd.PersistentFlags().
		BoolP(
			"insecure-skip-verify", "S",
			s.configs.CertInsecureSkipVerify,
			"Disable the certification validation. PLEASE, try not to use it",
		)

	startCmd.PersistentFlags().
		StringP(
			"certificate-path", "C",
			s.configs.CertPath,
			`Path to certificate of authority. Example -C="example/ca.crt"`,
		)

	startCmd.PersistentFlags().
		BoolP(
			"enable-commit-author", "G",
			s.configs.EnableCommitAuthor,
			"Enable to search commit author of vulnerabilities",
		)

	startCmd.PersistentFlags().
		StringP(
			"repository-name", "n",
			s.configs.RepositoryName,
			"Send repository name to Horusec server, by default sends the actual directory name",
		)

	startCmd.PersistentFlags().
		StringSliceP(
			"false-positive", "F",
			s.configs.FalsePositiveHashes,
			`Ignore a vulnerability by hash and set it to be false positive. Example -F="hash1, hash2"`,
		)

	startCmd.PersistentFlags().
		StringSliceP(
			"risk-accept", "R",
			s.configs.RiskAcceptHashes,
			`Ignore a vulnerability by hash and set it to be risk accept. Example -R="hash1, hash2"`,
		)

	startCmd.PersistentFlags().
		StringP(
			"container-bind-project-path", "P",
			s.configs.ContainerBindProjectPath,
			"Project path in host to be used on Docker when running Horusec inside a container",
		)

	startCmd.PersistentFlags().
		StringP(
			"custom-rules-path", "c",
			s.configs.CustomRulesPath,
			"Path with custom rules that should be used by Horusec engine",
		)

	startCmd.PersistentFlags().
		BoolP(
			"information-severity", "I",
			s.configs.EnableInformationSeverity,
			"Enable information severity vulnerabilities. Information vulnerabilities can contain a lot of false positives",
		)

	startCmd.PersistentFlags().
		StringSlice(
			"show-vulnerabilities-types",
			s.configs.ShowVulnerabilitiesTypes,
			`Show vulnerabilities by types ("Vulnerability"|"Risk Accepted"|"False Positive"|"Corrected"). Example --show-vulnerabilities-types="Vulnerability, Risk Accepted"`,
		)

	startCmd.PersistentFlags().
		BoolP(
			"enable-owasp-dependency-check", "w",
			s.configs.EnableOwaspDependencyCheck,
			"Run Owasp Dependency Check tool https://github.com/jeremylong/DependencyCheck",
		)

	startCmd.PersistentFlags().
		BoolP(
			"enable-shellcheck", "j",
			s.configs.EnableShellCheck,
			`Run ShellCheck tool https://github.com/koalaman/shellcheck`,
		)

	if !dist.IsStandAlone() {
		startCmd.PersistentFlags().
			BoolP(
				"disable-docker", "D",
				s.configs.DisableDocker,
				"Run Horusec without docker. If enabled it will only run the following tools: horusec-csharp, horusec-kotlin, horusec-java, horusec-kubernetes, horusec-leaks, horusec-javascript, horusec-dart, horusec-nginx",
			)
	}

	return s.setDeprecatedFlags(startCmd)
}

func (s *Start) setDeprecatedFlags(cmd *cobra.Command) *cobra.Command {
	flags := cmd.PersistentFlags()

	if err := flags.MarkHidden("monitor-retry-count"); err != nil {
		logger.LogPanic(fmt.Sprintf(messages.PanicMarkHiddenFlag, "monitor-retry-count"), err)
	}

	if err := flags.MarkDeprecated(
		"monitor-retry-count", "monitor component no longer exists in Horusec. Use only --analysis-timeout.",
	); err != nil {
		logger.LogPanic(fmt.Sprintf(messages.PanicMarkDeprecatedFlag, "monitor-retry-count"), err)
	}

	return cmd
}

func (s *Start) runE(cmd *cobra.Command, _ []string) error {
	totalVulns, err := s.startAnalysis(cmd)
	if err != nil {
		return err
	}

	if totalVulns > 0 && s.configs.ReturnErrorIfFoundVulnerability {
		cmd.SetUsageFunc(func(command *cobra.Command) error {
			return nil
		})

		return errors.New("analysis finished with blocking vulnerabilities")
	}
	return nil
}

func (s *Start) startAnalysis(cmd *cobra.Command) (totalVulns int, err error) {
	if err := s.askIfRunInDirectorySelected(s.isRunPromptQuestion(cmd)); err != nil {
		return 0, err
	}
	if err := s.validateConfig(); err != nil {
		return 0, err
	}
	return s.executeAnalysisDirectory()
}

func (s *Start) validateConfig() error {
	if err := usecases.ValidateConfig(s.configs); err != nil {
		return err
	}

	if err := s.validateRequirements(); err != nil {
		return err
	}

	logger.LogDebugWithLevel(messages.MsgDebugShowConfigs + string(s.configs.Bytes()))
	return nil
}

func (s *Start) validateRequirements() error {
	if s.configs.EnableGitHistoryAnalysis {
		if err := s.requirements.ValidateGit(); err != nil {
			return err
		}
	}

	if !s.configs.DisableDocker {
		if err := s.requirements.ValidateDocker(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Start) isRunPromptQuestion(cmd *cobra.Command) bool {
	flagChanged := cmd.Flags().Changed("project-path")
	if flagChanged {
		return false
	}
	currentPath, err := os.Getwd()
	if err == nil && s.configs.ProjectPath != currentPath {
		return false
	}
	return true
}

func (s *Start) executeAnalysisDirectory() (totalVulns int, err error) {
	if s.analyzer == nil {
		s.analyzer = analyzer.New(s.configs)
	}

	return s.analyzer.Analyze()
}

func (s *Start) askIfRunInDirectorySelected(shouldAsk bool) error {
	if shouldAsk {
		response, err := s.prompt.Ask(
			fmt.Sprintf("The folder selected is: [%s]. Proceed? [Y/n]", s.configs.ProjectPath),
			"Y")
		if err != nil {
			logger.LogWarnWithLevel(messages.MsgWarnWhenAskDirToRun, err.Error())
			return err
		}
		return s.validateReplyOfAsk(response)
	}
	return nil
}

func (s *Start) validateReplyOfAsk(response string) error {
	if !strings.EqualFold(response, "y") && !strings.EqualFold(response, "n") {
		logger.LogErrorWithLevel(messages.MsgErrorReplayWrong+response, errors.New("reply invalid"))
		return s.askIfRunInDirectorySelected(true)
	}
	if strings.EqualFold(response, "n") {
		return errors.New(messages.MsgErrorAskForUserCancelled)
	}
	return nil
}
