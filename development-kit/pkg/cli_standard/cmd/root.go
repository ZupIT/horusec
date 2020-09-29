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

package cmd

import (
	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/config"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/spf13/cobra"
)

func InitFlags(configs *config.Config, rootCmd *cobra.Command) {
	rootCmd.PersistentFlags().StringVarP(
		&configs.LogLevel, "log-level", "l", logger.InfoLevel.String(),
		"Set verbose level of the CLI. Log Level enable is: "+
			"\"panic\",\"fatal\",\"error\",\"warn\",\"info\",\"debug\",\"trace\"")
	rootCmd.PersistentFlags().StringVarP(&configs.OutputFilePath, "output-file-path", "o",
		configs.GetOutputFilePath(),
		"You can configure the output JSON location. Example: -o=\"/tmp/output.json\"")
	rootCmd.PersistentFlags().StringVarP(&configs.ProjectPath, "project-path", "p",
		configs.GetProjectPath(),
		"You can configure the path to run analysis. Example: -p=\"/home/user/my-project\"")

	cobra.OnInitialize(func() {
		logger.SetLogLevel(configs.LogLevel)
	})
}
