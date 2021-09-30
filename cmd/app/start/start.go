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

	"github.com/ZupIT/horusec/internal/controllers/printresults"

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
	Analyze() error
}

// Prompt is the interface that interact with use terminal prompt
//
// Ask read from stdin and return the user input
type Prompt interface {
	Ask(label, defaultValue string) (string, error)
}

// UseCase is the interface that validate the configurations
type UseCase interface {
	ValidateConfigs(config *config.Config) error
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

// nolint:funlen,lll // method is not necessary funlen
func (s *Start) CreateStartCommand() *cobra.Command {
	startCmd := &cobra.Command{
		Use:     "start",
		Short:   "Start horusec-cli",
		Long:    "Start the Horusec' analysis in the current path",
		Example: "horusec start",
		PreRunE: s.configs.PreRun,
		RunE:    s.runE,
	}

	startCmd.PersistentFlags().
		Int64VarP(
			&s.configs.MonitorRetryInSeconds,
			"monitor-retry-count", "m",
			s.configs.MonitorRetryInSeconds,
			"The number of retries for the monitor.",
		)

	startCmd.PersistentFlags().
		StringVarP(
			&s.configs.PrintOutputType,
			"output-format", "o",
			s.configs.PrintOutputType,
			"The format for the output to be shown. Options are: text (stdout), json, sonarqube",
		)

	startCmd.PersistentFlags().
		StringSliceVarP(
			&s.configs.SeveritiesToIgnore,
			"ignore-severity", "s",
			s.configs.SeveritiesToIgnore,
			"The level of vulnerabilities to ignore in the output. Example: -s=\"LOW, MEDIUM, HIGH\"",
		)

	startCmd.PersistentFlags().
		StringVarP(
			&s.configs.JSONOutputFilePath,
			"json-output-file", "O",
			s.configs.JSONOutputFilePath,
			"If your pass output-format you can configure the output JSON location. Example: -O=\"/tmp/output.json\"",
		)

	startCmd.PersistentFlags().
		StringSliceVarP(
			&s.configs.FilesOrPathsToIgnore,
			"ignore", "i",
			s.configs.FilesOrPathsToIgnore,
			"Paths to ignore in the analysis. Example: -i=\"/home/user/project/assets, /home/user/project/deployments\"",
		)

	startCmd.PersistentFlags().
		StringVarP(
			&s.configs.HorusecAPIUri,
			"horusec-url", "u",
			s.configs.HorusecAPIUri,
			"The Horusec API address to access the analysis engine",
		)

	startCmd.PersistentFlags().
		Int64VarP(
			&s.configs.TimeoutInSecondsRequest,
			"request-timeout", "r",
			s.configs.TimeoutInSecondsRequest,
			"The timeout threshold for the request to the Horusec API",
		)

	startCmd.PersistentFlags().
		Int64VarP(
			&s.configs.TimeoutInSecondsAnalysis,
			"analysis-timeout", "t",
			s.configs.TimeoutInSecondsAnalysis,
			"The timeout threshold for the Horusec CLI wait for the analysis to complete.",
		)

	startCmd.PersistentFlags().
		StringVarP(
			&s.configs.RepositoryAuthorization,
			"authorization", "a",
			s.configs.RepositoryAuthorization,
			"The authorization token for the Horusec API",
		)

	startCmd.PersistentFlags().
		StringToStringVar(
			&s.configs.Headers,
			"headers",
			s.configs.Headers,
			"The headers dynamic to send on request in Horusec API. Example --headers=\"{\"X-Auth-Service\": \"my-value\"}\"",
		)

	startCmd.PersistentFlags().
		BoolVarP(
			&s.configs.ReturnErrorIfFoundVulnerability,
			"return-error", "e",
			s.configs.ReturnErrorIfFoundVulnerability,
			"The return-error is the option to check if you can return \"exit(1)\" if found vulnerabilities. Example -e=\"true\"",
		)

	startCmd.PersistentFlags().
		StringVarP(
			&s.configs.ProjectPath,
			"project-path", "p",
			s.configs.ProjectPath,
			"Path to run an analysis in your project",
		)

	startCmd.PersistentFlags().
		BoolVar(
			&s.configs.EnableGitHistoryAnalysis,
			"enable-git-history",
			s.configs.EnableGitHistoryAnalysis,
			"When this value is \"true\" we will run tool gitleaks and search vulnerability in all git history of the project. Example --enable-git-history=\"true\"",
		)

	startCmd.PersistentFlags().
		BoolVarP(
			&s.configs.CertInsecureSkipVerify,
			"insecure-skip-verify", "S",
			s.configs.CertInsecureSkipVerify,
			"Insecure skip verify cert authority. PLEASE, try not to use it. Example -S=\"true\"",
		)

	startCmd.PersistentFlags().
		StringVarP(
			&s.configs.CertPath,
			"certificate-path", "C",
			s.configs.CertPath,
			"Path to certificate of authority. Example -C=\"/example/ca.crt\"",
		)

	startCmd.PersistentFlags().
		BoolVarP(
			&s.configs.EnableCommitAuthor,
			"enable-commit-author", "G",
			s.configs.EnableCommitAuthor,
			"Used to enable or disable search with vulnerability author. Example -G=\"true\"",
		)

	startCmd.PersistentFlags().
		StringVarP(
			&s.configs.RepositoryName,
			"repository-name", "n",
			s.configs.RepositoryName,
			"Used to send repository name to horus server. Example -n=\"horus\"",
		)

	startCmd.PersistentFlags().
		StringSliceVarP(
			&s.configs.FalsePositiveHashes,
			"false-positive", "F",
			s.configs.FalsePositiveHashes,
			"Used to ignore a vulnerability by hash and setting it to be of the false positive type. Example -F=\"hash1, hash2\"",
		)

	startCmd.PersistentFlags().
		StringSliceVarP(
			&s.configs.RiskAcceptHashes,
			"risk-accept", "R",
			s.configs.RiskAcceptHashes,
			"Used to ignore a vulnerability by hash and setting it to be of the risk accept type. Example -R=\"hash3, hash4\"",
		)

	startCmd.PersistentFlags().
		StringVarP(
			&s.configs.ContainerBindProjectPath,
			"container-bind-project-path", "P",
			s.configs.ContainerBindProjectPath,
			"Used to pass project path in host when running horusec cli inside a container.",
		)

	// TODO: This flag may have a bug
	startCmd.PersistentFlags().
		StringVarP(
			&s.configs.ContainerBindProjectPath,
			"custom-rules-path", "c",
			s.configs.ContainerBindProjectPath,
			"Used to pass the path to the horusec custom rules file. Example: -c=\"./horusec/horusec-custom-rules.json\".",
		)

	startCmd.PersistentFlags().
		BoolVarP(
			&s.configs.EnableInformationSeverity,
			"information-severity", "I",
			s.configs.EnableInformationSeverity,
			"Used to enable or disable information severity vulnerabilities, information vulnerabilities can contain a lot of false positives. Example: -I=\"true\"",
		)

	startCmd.PersistentFlags().
		StringSliceVar(
			&s.configs.ShowVulnerabilitiesTypes,
			"show-vulnerabilities-types",
			s.configs.ShowVulnerabilitiesTypes,
			"Used to show in the output vulnerabilities of types: Vulnerability, Risk Accepted, False Positive, Corrected. Example --show-vulnerabilities-types=\"Vulnerability, Risk Accepted\"",
		)

	startCmd.PersistentFlags().
		BoolVarP(
			&s.configs.EnableOwaspDependencyCheck,
			"enable-owasp-dependency-check", "w",
			s.configs.EnableOwaspDependencyCheck,
			"Enable owasp dependency check. Example -w=\"true\". Default: false",
		)

	startCmd.PersistentFlags().
		BoolVarP(
			&s.configs.EnableShellCheck,
			"enable-shellcheck", "j",
			s.configs.EnableShellCheck,
			"Enable shellcheck. Example -h=\"true\". Default: false",
		)

	if !dist.IsStandAlone() {
		startCmd.PersistentFlags().
			BoolVarP(
				&s.configs.DisableDocker,
				"disable-docker", "D",
				s.configs.DisableDocker,
				"Used to run horusec without docker if enabled it will only run the following tools: horusec-csharp, horusec-kotlin, horusec-java, horusec-kubernetes, horusec-leaks, horusec-nodejs, horusec-dart, horusec-nginx. Example: -D=\"true\"",
			)
	}

	return startCmd
}

func (s *Start) runE(cmd *cobra.Command, _ []string) error {
	if err := s.startAnalysis(cmd); err != nil {
		if errors.Is(err, printresults.ErrorUnknownVulnerabilitiesFound) {
			if s.configs.ReturnErrorIfFoundVulnerability {
				cmd.SetUsageFunc(func(command *cobra.Command) error {
					return nil
				})
				return errors.New("analysis finished with blocking vulnerabilities")
			}
			return nil
		}
		return err
	}
	return nil
}

func (s *Start) startAnalysis(cmd *cobra.Command) error {
	if err := s.askIfRunInDirectorySelected(s.isRunPromptQuestion(cmd)); err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorWhenAskDirToRun, err)
		return err
	}
	if err := s.configsValidations(cmd); err != nil {
		return err
	}
	return s.executeAnalysisDirectory()
}

func (s *Start) configsValidations(cmd *cobra.Command) error {
	if err := s.useCases.ValidateConfigs(s.configs); err != nil {
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

func (s *Start) executeAnalysisDirectory() error {
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
