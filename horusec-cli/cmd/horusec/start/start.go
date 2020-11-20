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

	"github.com/ZupIT/horusec/horusec-cli/internal/controllers/requirements"

	"github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
	"github.com/ZupIT/horusec/horusec-cli/internal/usecases/cli"

	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-cli/internal/controllers/analyser"
	"github.com/ZupIT/horusec/horusec-cli/internal/utils/prompt"
	"github.com/spf13/cobra"
)

type IStart interface {
	CreateCobraCmd() *cobra.Command
}

type Start struct {
	useCases           cli.Interface
	configs            *config.Config
	analyserController analyser.Interface
	startPrompt        prompt.Interface
}

func NewStartCommand(configs *config.Config) IStart {
	return &Start{
		useCases:    cli.NewCLIUseCases(),
		configs:     configs,
		startPrompt: prompt.NewPrompt(),
	}
}

func (s *Start) CreateCobraCmd() *cobra.Command {
	startCmd := &cobra.Command{
		Use:     "start",
		Short:   "Start horusec-cli",
		Long:    "Start the Horusec' analysis in the current path",
		Example: "horusec start",
		RunE:    s.runECobraCmd,
	}
	s.loadFlags(startCmd)
	return startCmd
}

func (s *Start) runECobraCmd(cmd *cobra.Command, _ []string) error {
	totalVulns, err := s.startAnalysis(cmd)
	if err != nil {
		return err
	}

	if totalVulns > 0 && s.configs.GetReturnErrorIfFoundVulnerability() {
		cmd.SetUsageFunc(func(command *cobra.Command) error {
			return nil
		})

		return errors.New("analysis finished with blocking vulnerabilities")
	}
	return nil
}

func (s *Start) startAnalysis(cmd *cobra.Command) (totalVulns int, err error) {
	if err := s.askIfRunInDirectorySelected(s.isRunPromptQuestion(cmd)); err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorWhenAskDirToRun, err, logger.ErrorLevel)
		return 0, err
	}
	if err := s.configsValidations(cmd); err != nil {
		return 0, err
	}
	return s.executeAnalysisDirectory()
}

func (s *Start) configsValidations(cmd *cobra.Command) error {
	if err := s.useCases.ValidateConfigs(s.configs); err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorInvalidConfigs, err, logger.ErrorLevel)
		_ = cmd.Help()
		return err
	}
	s.configs = s.useCases.NormalizeConfigs(s.configs)
	if s.configs.GetEnableGitHistoryAnalysis() {
		requirements.NewRequirements().ValidateGit()
	}
	logger.LogDebugWithLevel(messages.MsgDebugShowConfigs+string(s.configs.ToBytes(true)), logger.DebugLevel)
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
	if s.analyserController == nil {
		s.analyserController = analyser.NewAnalyser(s.configs)
	}

	return s.analyserController.AnalysisDirectory()
}

func (s *Start) askIfRunInDirectorySelected(shouldAsk bool) error {
	if shouldAsk {
		response, err := s.startPrompt.Ask(
			fmt.Sprintf("The folder selected is: [%s]. Proceed? [Y/n]", s.configs.GetProjectPath()),
			"Y")
		if err != nil {
			return err
		}
		return s.validateReplyOfAsk(response)
	}
	return nil
}

func (s *Start) validateReplyOfAsk(response string) error {
	if !strings.EqualFold(response, "y") && !strings.EqualFold(response, "n") {
		logger.LogErrorWithLevel("Your response was: '"+response+"' Please type Y or N",
			errors.New("reply invalid"), logger.ErrorLevel)
		return s.askIfRunInDirectorySelected(true)
	}
	if strings.EqualFold(response, "n") {
		return errors.New("{HORUSEC_CLI} Operation was canceled by user")
	}
	return nil
}

//nolint
func (s *Start) loadFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().
		Int64VarP(&s.configs.MonitorRetryInSeconds, "monitor-retry-count", "m", s.configs.GetMonitorRetryInSeconds(),
			"The number of retries for the monitor.")
	cmd.PersistentFlags().
		StringVarP(&s.configs.PrintOutputType, "output-format", "o", s.configs.GetPrintOutputType(),
			"The format for the output to be shown. Options are: text (stdout), json, sonarqube")
	cmd.PersistentFlags().
		StringVarP(&s.configs.TypesOfVulnerabilitiesToIgnore, "ignore-severity", "s", s.configs.GetTypesOfVulnerabilitiesToIgnore(),
			"The level of vulnerabilities to ignore in the output. Example: -s=\"LOW, MEDIUM, NOSEC\"")
	cmd.PersistentFlags().
		StringVarP(&s.configs.JSONOutputFilePath, "json-output-file", "O", s.configs.GetJSONOutputFilePath(),
			"If your pass output-format you can configure the output JSON location. Example: -O=\"/tmp/output.json\"")
	cmd.PersistentFlags().
		StringVarP(&s.configs.FilesOrPathsToIgnore, "ignore", "i", s.configs.GetFilesOrPathsToIgnore(),
			"Paths to ignore in the analysis. Example: -i=\"/home/user/project/assets, /home/user/project/deployments\"")
	cmd.PersistentFlags().
		StringVarP(&s.configs.HorusecAPIUri, "horusec-url", "u", s.configs.GetHorusecAPIUri(),
			"The Horusec API address to access the analysis engine")
	cmd.PersistentFlags().
		Int64VarP(&s.configs.TimeoutInSecondsRequest, "request-timeout", "r", s.configs.GetTimeoutInSecondsRequest(),
			"The timeout threshold for the request to the Horusec API")
	cmd.PersistentFlags().
		Int64VarP(&s.configs.TimeoutInSecondsAnalysis, "analysis-timeout", "t", s.configs.GetTimeoutInSecondsAnalysis(),
			"The timeout threshold for the Horusec CLI wait for the analysis to complete.")
	cmd.PersistentFlags().
		StringVarP(&s.configs.RepositoryAuthorization, "authorization", "a", s.configs.GetRepositoryAuthorization(),
			"The authorization token for the Horusec API")
	cmd.PersistentFlags().
		BoolVarP(&s.configs.ReturnErrorIfFoundVulnerability, "return-error", "e", s.configs.GetReturnErrorIfFoundVulnerability(),
			"The return-error is the option to check if you can return \"exit(1)\" if found vulnerabilities. Example -e=\"true\"")
	cmd.PersistentFlags().
		StringVarP(&s.configs.ProjectPath, "project-path", "p", s.configs.GetProjectPath(),
			"Path to run an analysis in your project")
	cmd.PersistentFlags().
		StringVarP(&s.configs.FilterPath, "filter-path", "f", s.configs.GetFilterPath(),
			"Filter the path to run the analysis")
	cmd.PersistentFlags().
		BoolVar(&s.configs.EnableGitHistoryAnalysis, "enable-git-history", s.configs.GetEnableGitHistoryAnalysis(),
			"When this value is \"true\" we will run tool gitleaks and search vulnerability in all git history of the project. Example --enable-git-history=\"true\"")
	cmd.PersistentFlags().
		BoolVarP(&s.configs.CertInsecureSkipVerify, "insecure-skip-verify", "S", s.configs.GetCertInsecureSkipVerify(),
			"Insecure skip verify cert authority. PLEASE, try not to use it. Example -S=\"true\"")
	cmd.PersistentFlags().
		StringVarP(&s.configs.CertPath, "certificate-path", "C", s.configs.GetCertPath(),
			"Path to certificate of authority. Example -C=\"/example/ca.crt\"")
	cmd.PersistentFlags().
		BoolVarP(&s.configs.EnableCommitAuthor, "enable-commit-author", "G", s.configs.IsCommitAuthorEnable(),
			"Used to enable or disable search with vulnerability author. Example -G=\"true\"")
	cmd.PersistentFlags().
		StringVarP(&s.configs.RepositoryName, "repository-name", "n", s.configs.GetRepositoryName(),
			"Used to send repository name to horus server. Example -n=\"horus\"")
	cmd.PersistentFlags().
		StringVarP(&s.configs.FalsePositiveHashes, "false-positive", "F", s.configs.GetFalsePositiveHashes(),
			"Used to ignore a vulnerability by hash and setting it to be of the false positive type. Example -F=\"hash1, hash2\"")
	cmd.PersistentFlags().
		StringVarP(&s.configs.RiskAcceptHashes, "risk-accept", "R", s.configs.GetRiskAcceptHashes(),
			"Used to ignore a vulnerability by hash and setting it to be of the risk accept type. Example -R=\"hash3, hash4\"")
	cmd.PersistentFlags().
		StringVarP(&s.configs.ToolsToIgnore, "tools-ignore", "T", s.configs.GetToolsToIgnore(),
			"Tools to ignore in the analysis. Available are: GoSec,SecurityCodeScan,Brakeman,Safety,Bandit,NpmAudit,YarnAudit,SpotBugs,HorusecKotlin,HorusecJava,HorusecLeaks,GitLeaks,TfSec,Semgrep,HorusecCsharp,HorusecNodeJS,HorusecKubernetes. Example: -T=\"GoSec, Brakeman\"")
}
