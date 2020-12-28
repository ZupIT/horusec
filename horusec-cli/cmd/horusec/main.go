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
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-cli/cmd/horusec/start"
	"github.com/ZupIT/horusec/horusec-cli/cmd/horusec/version"
	"github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/spf13/cobra"
	"os"
)

var configs = config.NewConfig()
var rootCmd = &cobra.Command{
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

// nolint
func init() {
	startCmd := start.NewStartCommand(configs)
	_ = rootCmd.PersistentFlags().String("log-level", configs.GetLogLevel(), "Set verbose level of the CLI. Log Level enable is: \"panic\",\"fatal\",\"error\",\"warn\",\"info\",\"debug\",\"trace\"")
	_ = rootCmd.PersistentFlags().String("config-file-path", configs.GetConfigFilePath(), "Path of the file horusec-config.json to setup content of horusec")
	rootCmd.AddCommand(version.NewVersionCommand().CreateCobraCmd())
	rootCmd.AddCommand(startCmd.CreateStartCommand())
	cobra.OnInitialize(func() {
		startCmd.SetGlobalCmd(rootCmd)
	})
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}
