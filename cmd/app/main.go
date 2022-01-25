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

	engine "github.com/ZupIT/horusec-engine"
	"github.com/spf13/cobra"

	"github.com/ZupIT/horusec/cmd/app/generate"
	"github.com/ZupIT/horusec/cmd/app/start"
	"github.com/ZupIT/horusec/cmd/app/version"
	"github.com/ZupIT/horusec/config"
)

// nolint:funlen,lll
func main() {
	cfg := config.New()

	rootCmd := &cobra.Command{
		Use: "horusec",
		Short: `Horusec is an open source tool that orchestrates other security tools and identifies security flaws and vulnerabilities.
See more in https://docs.horusec.io/docs/overview
		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
		Example: `
# Horusec will ask in which directory the analysis should be performed. Default is the current path.
horusec start

# Use the current directory to run the analysis.
horusec start -p .

# Use a different path than the current one.
# Note that the configuration file will still be searched in the current path if "--config-file-path" flag is not passed.
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
			`Set log level ("panic"|"fatal"|"error"|"warn"|"info"|"debug"|"trace")`,
		)

	rootCmd.PersistentFlags().
		StringVar(
			&cfg.ConfigFilePath,
			"config-file-path",
			cfg.ConfigFilePath,
			"Path of the configuration file",
		)

	rootCmd.PersistentFlags().
		StringVarP(
			&cfg.LogFilePath,
			"log-file-path", "l",
			cfg.LogFilePath,
			"Path of log file",
		)

	rootCmd.AddCommand(version.CreateCobraCmd())
	rootCmd.AddCommand(startCmd.CreateStartCommand())
	rootCmd.AddCommand(generateCmd.CreateCobraCmd())

	cobra.OnInitialize(func() {
		engine.SetLogLevel(cfg.LogLevel)
	})
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
