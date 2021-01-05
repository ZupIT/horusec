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

package run

import (
	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/config"
	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/internal/helpers/messages"
	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/internal/usecases/cli"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/spf13/cobra"
)

type Run struct {
	controller IController
	configs    *config.Config
	useCases   cli.Interface
}

type IController interface {
	StartAnalysis() error
}

type ICommand interface {
	CreateCobraCmd() *cobra.Command
}

func NewRunCommand(configs *config.Config, controller IController) ICommand {
	return &Run{
		useCases:   cli.NewCLIUseCases(),
		controller: controller,
		configs:    configs,
	}
}

func (r *Run) CreateCobraCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "run",
		RunE: r.runECobraCmd,
	}
	return cmd
}

func (r *Run) runECobraCmd(cmd *cobra.Command, _ []string) error {
	if err := r.useCases.ValidateConfigs(r.configs); err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorInvalidConfigs, err)
		_ = cmd.Help()
		return err
	}
	r.configs = r.useCases.NormalizeConfigs(r.configs)
	logger.LogDebugWithLevel(messages.MsgDebugConfigWasValidated, r.configs)
	err := r.controller.StartAnalysis()
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorAnalysisFinished, err)
	} else {
		logger.LogDebugWithLevel(messages.MsgDebugAnalysisFinished)
	}
	return err
}
