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
	configs            config.IConfig
	analyserController analyser.Interface
	startPrompt        prompt.Interface
}

func NewStartCommand(configs config.IConfig) IStart {
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
	s.configs.NewConfigsFromCobraAndLoadsFlags(startCmd)
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
	s.configs.NormalizeConfigs()
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
