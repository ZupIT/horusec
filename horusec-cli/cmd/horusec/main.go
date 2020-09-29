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
	"fmt"
	"os"

	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-cli/cmd/horusec/start"
	"github.com/ZupIT/horusec/horusec-cli/cmd/horusec/version"
	"github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/ZupIT/horusec/horusec-cli/internal/controllers/requirements"
	"github.com/spf13/cobra"
)

var LogLevel = logger.InfoLevel.String()
var configs *config.Config

var rootCmd = &cobra.Command{
	Use:   "horusec",
	Short: "Horusec CLI prepares packages to be analyzed by the Horusec Analysis API",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger.LogPrint("Horusec Command Line IHelp is an orchestrates security," +
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
	//initialize empty config
	configs = &config.Config{}

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&LogLevel, "log-level", logger.InfoLevel.String(), "Set verbose level of the CLI. Log Level enable is: \"panic\",\"fatal\",\"error\",\"warn\",\"info\",\"debug\",\"trace\"")

	cobra.OnInitialize(initConfig)
}

func main() {
	requirements.NewRequirements().ValidateDocker()
	ExecuteCobra()
}

func ExecuteCobra() {
	setConfigsData()
	rootCmd.AddCommand(start.NewStartCommand(configs).CreateCobraCmd())
	rootCmd.AddCommand(version.NewVersionCommand().CreateCobraCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}

func setConfigsData() {
	path, _ := os.Getwd()
	configs.ConfigFilePath = fmt.Sprintf("%s/horusec-config.json", path)
	configs.SetConfigsFromViper()
	configs.SetConfigsFromEnvironments()
}

func initConfig() {
	logger.SetLogLevel(LogLevel)
}
