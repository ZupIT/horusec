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

package main

import (
	"os"

	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/cmd"
	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/cmd/run"
	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/cmd/version"
	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/config"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-java/internal/controllers"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "horusec-java",
	Short: "Horusec-java CLI",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger.LogPrint("Horusec Java Command Line Interface")
		return cmd.Help()
	},
	Example: `horusec-java run`,
}

var configs *config.Config

// nolint
func init() {
	configs = config.NewConfig()
	cmd.InitFlags(configs, rootCmd)
}

func main() {
	controller := controllers.NewAnalysis(configs)
	rootCmd.AddCommand(run.NewRunCommand(configs, controller).CreateCobraCmd())
	rootCmd.AddCommand(version.NewVersionCommand().CreateCobraCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}
