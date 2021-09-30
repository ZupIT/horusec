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
	"github.com/ZupIT/horusec/cmd/app/license"
	"os"

	"github.com/spf13/cobra"

	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/cmd/app/generate"
	"github.com/ZupIT/horusec/cmd/app/start"
	"github.com/ZupIT/horusec/cmd/app/version"
	"github.com/ZupIT/horusec/config"
)

// nolint:funlen,lll
func main() {
	cfg := config.New()

	rootCmd := &cobra.Command{
		Use:   "horusec",
		Short: "Horusec CLI prepares packages to be analyzed by the Horusec Analysis API",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.LogPrint("Horusec Command Line is an orchestrates security," +
				"tests and centralizes all results into a database for further analysis and metrics.")
			return cmd.Help()
		},
		Example: `
horusec start
horusec start -p="/home/user/projects/my-project"
`,
	}

	startCmd := start.NewStartCommand(cfg)
	generateCmd := generate.NewGenerateCommand(cfg)

	rootCmd.PersistentFlags().
		StringVar(
			&cfg.LogLevel,
			"log-level",
			cfg.LogLevel,
			"Set verbose level of the CLI. Log Level enable is: \"panic\",\"fatal\",\"error\",\"warn\",\"info\",\"debug\",\"trace\"",
		)

	rootCmd.PersistentFlags().
		StringVar(
			&cfg.ConfigFilePath,
			"config-file-path",
			cfg.ConfigFilePath,
			"Path of the file horusec-config.json to setup content of horusec",
		)

	rootCmd.PersistentFlags().
		StringVarP(
			&cfg.LogFilePath,
			"log-file-path", "l",
			cfg.LogFilePath,
			`set user defined log file path instead of default`,
		)

	rootCmd.AddCommand(version.NewVersionCommand(cfg).CreateCobraCmd())
	rootCmd.AddCommand(license.NewLicenseCommand(cfg).CreateLicenseCommand())
	rootCmd.AddCommand(startCmd.CreateStartCommand())
	rootCmd.AddCommand(generateCmd.CreateCobraCmd())

	cobra.OnInitialize(func() {
		engine.SetLogLevel(cfg.LogLevel)
	})

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
