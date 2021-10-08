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

	"github.com/ZupIT/horusec/internal/controllers/requirements"

	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/config/dist"
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/usecases/cli"

	"github.com/spf13/cobra"

	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/ZupIT/horusec/internal/controllers/analyzer"
	"github.com/ZupIT/horusec/internal/utils/prompt"
)

// Analyzer is the interface that execute the analysis on some directory.
//
// Analyze returns the total of vulnerabilies founded on directory
type Analyzer interface {
	Analyze() (int, error)
}

// Prompt is the interface that interact with use terminal prompt
//
// Ask read from stdin and return the user input
type Prompt interface {
	Ask(label, defaultValue string) (string, error)
}

// UseCase is the interface that validate the configurations
type UseCase interface {
	ValidateConfig(config *config.Config) error
}

// Requirements is the interface that validate Horusec dynamic
// requirements to execute analysis
type Requirements interface {
	ValidateDocker()
	ValidateGit()
}

type Start struct {
	useCases     UseCase
	configs      *config.Config
	analyzer     Analyzer
	prompt       Prompt
	requirements Requirements
}

func NewStartCommand(configs *config.Config) *Start {
	return &Start{
		configs:      configs,
		useCases:     cli.NewCLIUseCases(),
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
		Short:             "Start horusec-cli",
		Long:              "Start the Horusec' analysis in the current path",
		Example:           "horusec start",
		PersistentPreRunE: s.configs.PersistentPreRun,
		RunE:              s.runE,
	}

	startCmd.PersistentFlags().
		Int64P(
			"monitor-retry-count", "m",
			s.configs.MonitorRetryInSeconds,
			"The number of retries for the monitor.",
		)

	startCmd.PersistentFlags().
		StringP(
			"output-format", "o",
			s.configs.PrintOutputType,
			"The format for the output to be shown. Options are: text (stdout), json, sonarqube",
		)

	startCmd.PersistentFlags().
		StringSliceP(
			"ignore-severity", "s",
			s.configs.SeveritiesToIgnore,
			"The level of vulnerabilities to ignore in the output. Example: -s=\"LOW, MEDIUM, HIGH\"",
		)

	startCmd.PersistentFlags().
		StringP(
			"json-output-file", "O",
			s.configs.JSONOutputFilePath,
			"If your pass output-format you can configure the output JSON location. Example: -O=\"/tmp/output.json\"",
		)

	startCmd.PersistentFlags().
		StringSliceP(
			"ignore", "i",
			s.configs.FilesOrPathsToIgnore,
			"Paths to ignore in the analysis. Example: -i=\"/home/user/project/assets, /home/user/project/deployments\"",
		)

	startCmd.PersistentFlags().
		StringP(
			"horusec-url", "u",
			s.configs.HorusecAPIUri,
			"The Horusec API address to access the analysis engine",
		)

	startCmd.PersistentFlags().
		Int64P(
			"request-timeout", "r",
			s.configs.TimeoutInSecondsRequest,
			"The timeout threshold for the request to the Horusec API",
		)

	startCmd.PersistentFlags().
		Int64P(
			"analysis-timeout", "t",
			s.configs.TimeoutInSecondsAnalysis,
			"The timeout threshold for the Horusec CLI wait for the analysis to complete.",
		)

	startCmd.PersistentFlags().
		StringP(
			"authorization", "a",
			s.configs.RepositoryAuthorization,
			"The authorization token for the Horusec API",
		)

	startCmd.PersistentFlags().
		StringToString(
			"headers",
			s.configs.Headers,
			"The headers dynamic to send on request in Horusec API. Example --headers=\"{\"X-Auth-Service\": \"my-value\"}\"",
		)

	startCmd.PersistentFlags().
		BoolP(
			"return-error", "e",
			s.configs.ReturnErrorIfFoundVulnerability,
			"The return-error is the option to check if you can return \"exit(1)\" if found vulnerabilities. Example -e=\"true\"",
		)

	startCmd.PersistentFlags().
		StringP(
			"project-path", "p",
			s.configs.ProjectPath,
			"Path to run an analysis in your project",
		)

	startCmd.PersistentFlags().
		Bool(
			"enable-git-history",
			s.configs.EnableGitHistoryAnalysis,
			"When this value is \"true\" we will run tool gitleaks and search vulnerability in all git history of the project. Example --enable-git-history=\"true\"",
		)

	startCmd.PersistentFlags().
		BoolP(
			"insecure-skip-verify", "S",
			s.configs.CertInsecureSkipVerify,
			"Insecure skip verify cert authority. PLEASE, try not to use it. Example -S=\"true\"",
		)

	startCmd.PersistentFlags().
		StringP(
			"certificate-path", "C",
			s.configs.CertPath,
			"Path to certificate of authority. Example -C=\"/example/ca.crt\"",
		)

	startCmd.PersistentFlags().
		BoolP(
			"enable-commit-author", "G",
			s.configs.EnableCommitAuthor,
			"Used to enable or disable search with vulnerability author. Example -G=\"true\"",
		)

	startCmd.PersistentFlags().
		StringP(
			"repository-name", "n",
			s.configs.RepositoryName,
			"Used to send repository name to horus server. Example -n=\"horus\"",
		)

	startCmd.PersistentFlags().
		StringSliceP(
			"false-positive", "F",
			s.configs.FalsePositiveHashes,
			"Used to ignore a vulnerability by hash and setting it to be of the false positive type. Example -F=\"hash1, hash2\"",
		)

	startCmd.PersistentFlags().
		StringSliceP(
			"risk-accept", "R",
			s.configs.RiskAcceptHashes,
			"Used to ignore a vulnerability by hash and setting it to be of the risk accept type. Example -R=\"hash3, hash4\"",
		)

	startCmd.PersistentFlags().
		StringP(
			"container-bind-project-path", "P",
			s.configs.ContainerBindProjectPath,
			"Used to pass project path in host when running horusec cli inside a container.",
		)

	startCmd.PersistentFlags().
		StringP(
			"custom-rules-path", "c",
			s.configs.CustomRulesPath,
			"Used to pass the path to the horusec custom rules file. Example: -c=\"./horusec/horusec-custom-rules.json\".",
		)

	startCmd.PersistentFlags().
		BoolP(
			"information-severity", "I",
			s.configs.EnableInformationSeverity,
			"Used to enable or disable information severity vulnerabilities, information vulnerabilities can contain a lot of false positives. Example: -I=\"true\"",
		)

	startCmd.PersistentFlags().
		StringSlice(
			"show-vulnerabilities-types",
			s.configs.ShowVulnerabilitiesTypes,
			"Used to show in the output vulnerabilities of types: Vulnerability, Risk Accepted, False Positive, Corrected. Example --show-vulnerabilities-types=\"Vulnerability, Risk Accepted\"",
		)

	startCmd.PersistentFlags().
		BoolP(
			"enable-owasp-dependency-check", "w",
			s.configs.EnableOwaspDependencyCheck,
			"Enable owasp dependency check. Example -w=\"true\". Default: false",
		)

	startCmd.PersistentFlags().
		BoolP(
			"enable-shellcheck", "j",
			s.configs.EnableShellCheck,
			"Enable shellcheck. Example -h=\"true\". Default: false",
		)

	if !dist.IsStandAlone() {
		startCmd.PersistentFlags().
			BoolP(
				"disable-docker", "D",
				s.configs.DisableDocker,
				"Used to run horusec without docker if enabled it will only run the following tools: horusec-csharp, horusec-kotlin, horusec-java, horusec-kubernetes, horusec-leaks, horusec-nodejs, horusec-dart, horusec-nginx. Example: -D=\"true\"",
			)
	}

	return startCmd
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
		logger.LogErrorWithLevel(messages.MsgErrorWhenAskDirToRun, err)
		return 0, err
	}
	if err := s.configsValidations(cmd); err != nil {
		return 0, err
	}
	return s.executeAnalysisDirectory()
}

func (s *Start) configsValidations(cmd *cobra.Command) error {
	if err := s.useCases.ValidateConfig(s.configs); err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorInvalidConfigs, err)
		_ = cmd.Help()
		return err
	}

	s.validateRequirements()

	logger.LogDebugWithLevel(messages.MsgDebugShowConfigs + string(s.configs.ToBytes(true)))
	return nil
}

func (s *Start) validateRequirements() {
	if s.configs.EnableGitHistoryAnalysis {
		s.requirements.ValidateGit()
	}

	if !s.configs.DisableDocker {
		s.requirements.ValidateDocker()
	}
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
		s.analyzer = analyzer.NewAnalyzer(s.configs)
	}

	return s.analyzer.Analyze()
}

func (s *Start) askIfRunInDirectorySelected(shouldAsk bool) error {
	if shouldAsk {
		response, err := s.prompt.Ask(
			fmt.Sprintf("The folder selected is: [%s]. Proceed? [Y/n]", s.configs.ProjectPath),
			"Y")
		if err != nil {
			logger.LogWarnWithLevel(messages.MsgErrorWhenAskDirToRun+`
Please use the command below informing the directory you want to run the analysis: 
horusec start -p ./
`, err.Error())
			return nil
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
		return errors.New("{HORUSEC_CLI} Operation was canceled by user")
	}
	return nil
}
