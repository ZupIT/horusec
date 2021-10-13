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
	"github.com/ZupIT/horusec/internal/controllers/requirements"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	"os"
	"strings"

	"github.com/ZupIT/horusec/config"
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
		RunE:              s.runE,
	}

	f:= startCmd.Flags()
	startFlags(f)

	if err:=viper.BindPFlags(f);err!= nil{
		return nil
	}
	return startCmd
}
func DecoderConfigOptions(config *mapstructure.DecoderConfig) {
	config.DecodeHook = mapstructure.ComposeDecodeHookFunc(
		mapstructure.StringToTimeDurationHookFunc(),
		mapstructure.StringToSliceHookFunc(","),
	)
}

func (s *Start) runE(cmd *cobra.Command, _ []string) error {
	var config NewConfig
	if err := viper.Unmarshal(&config, DecoderConfigOptions); err != nil {
		return fmt.Errorf("parse config: %v", err)
	}
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
