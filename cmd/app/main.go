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
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/cmd/app/generate"
	"github.com/ZupIT/horusec/cmd/app/start"
	"github.com/ZupIT/horusec/cmd/app/version"
	"github.com/ZupIT/horusec/config"
)
//The config file path
var cfgFilePath string
//The dry-run flag
var dryRun bool

var appName = "horusec"

var 	rootCmd = &cobra.Command{
	Use:   "horusec",
	Short: "Horusec CLI prepares packages to be analyzed by the Horusec Analysis API",

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			return err
		}
		if dryRun {
			var config start.NewConfig
			if err := viper.Unmarshal(&config, start.DecoderConfigOptions); err != nil {
				return fmt.Errorf("parse config: %v", err)
			}

			j, err := json.MarshalIndent(config, " ", " ")
			if err != nil {
				return err
			}

			fmt.Println(string(j))
			os.Exit(0)
		}
		return nil
	},

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

func init(){
	cfg := config.New()
	cfg.ConfigFilePath =""
	//logrus.SetFormatter(&logrus.JSONFormatter{
	//	TimestampFormat: time.RFC3339,
	//	FieldMap: logrus.FieldMap{
	//		logrus.FieldKeyTime:  "timestamp",
	//		logrus.FieldKeyLevel: "level",
	//		logrus.FieldKeyMsg:   "message",
	//		logrus.FieldKeyFunc:  "caller",
	//	},
	//})
	//
	//logrus.SetReportCaller(true)
	cobra.OnInitialize(func() {
		engine.SetLogLevel(cfg.LogLevel)
		if err:= initConfig() ; err != nil{
			logrus.Error(err.Error())
			os.Exit(1)
		}
	})

	rootCmd.PersistentFlags().
		StringVar(
			&cfg.LogLevel,
			"log-level",
			cfg.LogLevel,
			"Set verbose level of the CLI. Log Level enable is: \"panic\",\"fatal\",\"error\",\"warn\",\"info\",\"debug\",\"trace\"",
		)

	rootCmd.PersistentFlags().
		StringVar(
			&cfgFilePath,
			"config-file-path",
			"",
			"Path of the file horusec-config.json to setup content of horusec",
		)

	rootCmd.PersistentFlags().
		StringVarP(
			&cfg.LogFilePath,
			"log-file-path", "l",
			cfg.LogFilePath,
			`set user defined log file path instead of default`,
		)
	rootCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "Print the configuration")
	startCmd := start.NewStartCommand(cfg)
	generateCmd := generate.NewGenerateCommand(cfg)


	rootCmd.AddCommand(version.CreateCobraCmd())
	rootCmd.AddCommand(startCmd.CreateStartCommand())
	rootCmd.AddCommand(generateCmd.CreateCobraCmd())

}
// nolint:funlen,lll
func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() error{
	if cfgFilePath != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFilePath)
	} else {
		// Find working directory.
		wd, err := os.Getwd()
		if err != nil {
			logger.LogWarn("Error to get current working directory: %v", err)
		}

		// Search config in home directory with name ".horusec" (without extension).
		viper.AddConfigPath(wd)
		viper.SetConfigName("horusec-config")
	}

	rep := strings.NewReplacer(".", "_", "-", "_")
	viper.SetEnvPrefix("")
	viper.SetEnvKeyReplacer(rep)
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		logrus.Infof("Using config file: %s", viper.ConfigFileUsed())
	}else {
		logrus.Warning(err)
	}
	return nil
}
