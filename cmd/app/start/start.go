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
	"github.com/ZupIT/horusec/internal/helpers/messages"
	"github.com/ZupIT/horusec/internal/usecases/cli"

	"github.com/spf13/cobra"

	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/ZupIT/horusec/internal/controllers/analyser"
	"github.com/ZupIT/horusec/internal/utils/prompt"
)

type IStart interface {
	SetGlobalCmd(globalCmd *cobra.Command)
	CreateStartCommand() *cobra.Command
}

type Start struct {
	useCases               cli.Interface
	configs                config.IConfig
	analyserController     analyser.Interface
	startPrompt            prompt.Interface
	globalCmd              *cobra.Command
	requirementsController requirements.IRequirements
}

func NewStartCommand(configs config.IConfig) IStart {
	return &Start{
		configs:                configs,
		globalCmd:              &cobra.Command{},
		useCases:               cli.NewCLIUseCases(),
		startPrompt:            prompt.NewPrompt(),
		requirementsController: requirements.NewRequirements(),
	}
}

func (s *Start) SetGlobalCmd(globalCmd *cobra.Command) {
	s.globalCmd = globalCmd
}

// nolint:funlen,lll // method is not necessary funlen
func (s *Start) CreateStartCommand() *cobra.Command {
	startCmd := &cobra.Command{
		Use:     "start",
		Short:   "Start horusec-cli",
		Long:    "Start the Horusec' analysis in the current path",
		Example: "horusec start",
		RunE:    s.runE,
	}
	_ = startCmd.PersistentFlags().
		Int64P("monitor-retry-count", "m", s.configs.GetMonitorRetryInSeconds(), "The number of retries for the monitor.")
	_ = startCmd.PersistentFlags().
		StringP("output-format", "o", s.configs.GetPrintOutputType(), "The format for the output to be shown. Options are: text (stdout), json, sonarqube")
	_ = startCmd.PersistentFlags().
		StringSliceP("ignore-severity", "s", s.configs.GetSeveritiesToIgnore(), "The level of vulnerabilities to ignore in the output. Example: -s=\"LOW, MEDIUM, HIGH\"")
	_ = startCmd.PersistentFlags().
		StringP("json-output-file", "O", s.configs.GetJSONOutputFilePath(), "If your pass output-format you can configure the output JSON location. Example: -O=\"/tmp/output.json\"")
	_ = startCmd.PersistentFlags().
		StringSliceP("ignore", "i", s.configs.GetFilesOrPathsToIgnore(), "Paths to ignore in the analysis. Example: -i=\"/home/user/project/assets, /home/user/project/deployments\"")
	_ = startCmd.PersistentFlags().
		StringP("horusec-url", "u", s.configs.GetHorusecAPIUri(), "The Horusec API address to access the analysis engine")
	_ = startCmd.PersistentFlags().
		Int64P("request-timeout", "r", s.configs.GetTimeoutInSecondsRequest(), "The timeout threshold for the request to the Horusec API")
	_ = startCmd.PersistentFlags().
		Int64P("analysis-timeout", "t", s.configs.GetTimeoutInSecondsAnalysis(), "The timeout threshold for the Horusec CLI wait for the analysis to complete.")
	_ = startCmd.PersistentFlags().
		StringP("authorization", "a", s.configs.GetRepositoryAuthorization(), "The authorization token for the Horusec API")
	_ = startCmd.PersistentFlags().
		StringToString("headers", s.configs.GetHeaders(), "The headers dynamic to send on request in Horusec API. Example --headers=\"{\"X-Auth-Service\": \"my-value\"}\"")
	_ = startCmd.PersistentFlags().
		BoolP("return-error", "e", s.configs.GetReturnErrorIfFoundVulnerability(), "The return-error is the option to check if you can return \"exit(1)\" if found vulnerabilities. Example -e=\"true\"")
	_ = startCmd.PersistentFlags().
		StringP("project-path", "p", s.configs.GetProjectPath(), "Path to run an analysis in your project")
	_ = startCmd.PersistentFlags().
		Bool("enable-git-history", s.configs.GetEnableGitHistoryAnalysis(), "When this value is \"true\" we will run tool gitleaks and search vulnerability in all git history of the project. Example --enable-git-history=\"true\"")
	_ = startCmd.PersistentFlags().
		BoolP("insecure-skip-verify", "S", s.configs.GetCertInsecureSkipVerify(), "Insecure skip verify cert authority. PLEASE, try not to use it. Example -S=\"true\"")
	_ = startCmd.PersistentFlags().
		StringP("certificate-path", "C", s.configs.GetCertPath(), "Path to certificate of authority. Example -C=\"/example/ca.crt\"")
	_ = startCmd.PersistentFlags().
		BoolP("enable-commit-author", "G", s.configs.GetEnableCommitAuthor(), "Used to enable or disable search with vulnerability author. Example -G=\"true\"")
	_ = startCmd.PersistentFlags().
		StringP("repository-name", "n", s.configs.GetRepositoryName(), "Used to send repository name to horus server. Example -n=\"horus\"")
	_ = startCmd.PersistentFlags().
		StringSliceP("false-positive", "F", s.configs.GetFalsePositiveHashes(), "Used to ignore a vulnerability by hash and setting it to be of the false positive type. Example -F=\"hash1, hash2\"")
	_ = startCmd.PersistentFlags().
		StringSliceP("risk-accept", "R", s.configs.GetRiskAcceptHashes(), "Used to ignore a vulnerability by hash and setting it to be of the risk accept type. Example -R=\"hash3, hash4\"")
	_ = startCmd.PersistentFlags().
		StringP("container-bind-project-path", "P", s.configs.GetContainerBindProjectPath(), "Used to pass project path in host when running horusec cli inside a container.")
	_ = startCmd.PersistentFlags().
		StringP("custom-rules-path", "c", s.configs.GetContainerBindProjectPath(), "Used to pass the path to the horusec custom rules file. Example: -c=\"./horusec/horusec-custom-rules.json\".")
	_ = startCmd.PersistentFlags().
		BoolP("disable-docker", "D", s.configs.GetEnableCommitAuthor(), "Used to run horusec without docker if enabled it will only run the following tools: horusec-csharp, horusec-kotlin, horusec-kubernetes, horusec-leaks, horusec-nodejs, horusec-dart, horusec-nginx. Example: -D=\"true\"")
	_ = startCmd.PersistentFlags().
		BoolP("information-severity", "I", s.configs.GetEnableInformationSeverity(), "Used to enable or disable information severity vulnerabilities, information vulnerabilities can contain a lot of false positives. Example: -I=\"true\"")
	_ = startCmd.PersistentFlags().
		StringSliceP("show-vulnerabilities-types", "", s.configs.GetShowVulnerabilitiesTypes(), "Used to show in the output vulnerabilities of types: Vulnerability, Risk Accepted, False Positive, Corrected. Example --show-vulnerabilities-types=\"Vulnerability, Risk Accepted\"")
	return startCmd
}

func (s *Start) setConfig(startCmd *cobra.Command) {
	s.configs = s.configs.NewConfigsFromCobraAndLoadsCmdGlobalFlags(s.globalCmd).NormalizeConfigs()
	s.configs = s.configs.NewConfigsFromViper().NormalizeConfigs()
	s.configs = s.configs.NewConfigsFromEnvironments().NormalizeConfigs()
	s.configs = s.configs.NewConfigsFromCobraAndLoadsCmdStartFlags(startCmd).NormalizeConfigs()
}

func (s *Start) runE(cmd *cobra.Command, _ []string) error {
	s.setConfig(cmd)
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
		logger.LogErrorWithLevel(messages.MsgErrorWhenAskDirToRun, err)
		return 0, err
	}
	if err := s.configsValidations(cmd); err != nil {
		return 0, err
	}
	return s.executeAnalysisDirectory()
}

func (s *Start) configsValidations(cmd *cobra.Command) error {
	if err := s.useCases.ValidateConfigs(s.configs); err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorInvalidConfigs, err)
		_ = cmd.Help()
		return err
	}

	s.configs.NormalizeConfigs()
	s.validateRequirements()

	logger.LogDebugWithLevel(messages.MsgDebugShowConfigs + string(s.configs.ToBytes(true)))
	return nil
}

func (s *Start) validateRequirements() {
	if s.configs.GetEnableGitHistoryAnalysis() {
		s.requirementsController.ValidateGit()
	}

	if !s.configs.GetDisableDocker() {
		s.requirementsController.ValidateDocker()
	}
}

func (s *Start) isRunPromptQuestion(cmd *cobra.Command) bool {
	flagChanged := cmd.Flags().Changed("project-path")
	if flagChanged {
		return false
	}
	currentPath, err := os.Getwd()
	if err == nil && s.configs.GetProjectPath() != currentPath {
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
