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
	engine "github.com/ZupIT/horusec-engine"
	"github.com/ZupIT/horusec/cmd/app/generate"
	"github.com/ZupIT/horusec/cmd/app/start"
	"github.com/ZupIT/horusec/cmd/app/version"
	"github.com/ZupIT/horusec/config"
	"github.com/mitchellh/go-homedir"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
)

//The config file path
var cfgFile string
var appName = "horusec_cli"

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

// nolint:funlen,lll
func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	logrus.SetOutput(os.Stdout)
	logrus.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "message",
			logrus.FieldKeyFunc:  "caller",
		},
	})

	logrus.SetReportCaller(true)

	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", fmt.Sprintf("config file (default is $HOME/.%s.yaml)", appName))

	cfg := config.New()
	cobra.OnInitialize(func() {
		engine.SetLogLevel(cfg.LogLevel)
		initConfig()
	})
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

	rootCmd.AddCommand(version.CreateCobraCmd())
	rootCmd.AddCommand(startCmd.CreateStartCommand())
	rootCmd.AddCommand(generateCmd.CreateCobraCmd())
	fmt.Println(viper.Get("HORUSEC_CLI_TIMEOUT_IN_SECONDS_ANALYSIS"))
	fmt.Println(viper.AllSettings())

}
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".pyokomon" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(fmt.Sprintf(".%s", appName))
	}

	rep := strings.NewReplacer(".", "_", "-", "_")
	viper.SetEnvPrefix(appName)
	viper.SetEnvKeyReplacer(rep)
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

type NewConfig struct {
	HorusecCliCertInsecureSkipVerify   bool   `json:"horusecCliCertInsecureSkipVerify"`
	HorusecCliCertPath                 string `json:"horusecCliCertPath"`
	HorusecCliContainerBindProjectPath string `json:"horusecCliContainerBindProjectPath"`
	HorusecCliCustomImages             struct {
		C          string `json:"c"`
		Csharp     string `json:"csharp"`
		Elixir     string `json:"elixir"`
		Generic    string `json:"generic"`
		Go         string `json:"go"`
		Hcl        string `json:"hcl"`
		Javascript string `json:"javascript"`
		Leaks      string `json:"leaks"`
		Php        string `json:"php"`
		Python     string `json:"python"`
		Ruby       string `json:"ruby"`
		Shell      string `json:"shell"`
	} `json:"horusecCliCustomImages"`
	HorusecCliCustomRulesPath           string        `json:"horusecCliCustomRulesPath"`
	HorusecCliDisableDocker             bool          `json:"horusecCliDisableDocker"`
	HorusecCliEnableCommitAuthor        bool          `json:"horusecCliEnableCommitAuthor"`
	HorusecCliEnableGitHistoryAnalysis  bool          `json:"horusecCliEnableGitHistoryAnalysis"`
	HorusecCliEnableInformationSeverity bool          `json:"horusecCliEnableInformationSeverity"`
	HorusecCliFalsePositiveHashes       []interface{} `json:"horusecCliFalsePositiveHashes"`
	HorusecCliFilesOrPathsToIgnore      []string      `json:"horusecCliFilesOrPathsToIgnore"`
	HorusecCliHeaders                   struct {
	} `json:"horusecCliHeaders"`
	HorusecCliHorusecAPIURI                   string        `json:"horusecCliHorusecApiUri"`
	HorusecCliJSONOutputFilepath              string        `json:"horusecCliJsonOutputFilepath"`
	HorusecCliMonitorRetryInSeconds           int           `json:"horusecCliMonitorRetryInSeconds"`
	HorusecCliPrintOutputType                 string        `json:"horusecCliPrintOutputType"`
	HorusecCliProjectPath                     string        `json:"horusecCliProjectPath"`
	HorusecCliRepositoryAuthorization         string        `json:"horusecCliRepositoryAuthorization"`
	HorusecCliRepositoryName                  string        `json:"horusecCliRepositoryName"`
	HorusecCliReturnErrorIfFoundVulnerability bool          `json:"horusecCliReturnErrorIfFoundVulnerability"`
	HorusecCliRiskAcceptHashes                []interface{} `json:"horusecCliRiskAcceptHashes"`
	HorusecCliSeveritiesToIgnore              []interface{} `json:"horusecCliSeveritiesToIgnore"`
	HorusecCliShowVulnerabilitiesTypes        []interface{} `json:"horusecCliShowVulnerabilitiesTypes"`
	HorusecCliTimeoutInSecondsAnalysis        int           `json:"horusecCliTimeoutInSecondsAnalysis"`
	HorusecCliTimeoutInSecondsRequest         int           `json:"horusecCliTimeoutInSecondsRequest"`
	HorusecCliToolsConfig                     struct {
		Bandit struct {
			Istoignore bool `json:"istoignore"`
		} `json:"Bandit"`
		Brakeman struct {
			Istoignore bool `json:"istoignore"`
		} `json:"Brakeman"`
		BundlerAudit struct {
			Istoignore bool `json:"istoignore"`
		} `json:"BundlerAudit"`
		Checkov struct {
			Istoignore bool `json:"istoignore"`
		} `json:"Checkov"`
		Flawfinder struct {
			Istoignore bool `json:"istoignore"`
		} `json:"Flawfinder"`
		GitLeaks struct {
			Istoignore bool `json:"istoignore"`
		} `json:"GitLeaks"`
		GoSec struct {
			Istoignore bool `json:"istoignore"`
		} `json:"GoSec"`
		HorusecEngine struct {
			Istoignore bool `json:"istoignore"`
		} `json:"HorusecEngine"`
		MixAudit struct {
			Istoignore bool `json:"istoignore"`
		} `json:"MixAudit"`
		NpmAudit struct {
			Istoignore bool `json:"istoignore"`
		} `json:"NpmAudit"`
		PhpCS struct {
			Istoignore bool `json:"istoignore"`
		} `json:"PhpCS"`
		Safety struct {
			Istoignore bool `json:"istoignore"`
		} `json:"Safety"`
		SecurityCodeScan struct {
			Istoignore bool `json:"istoignore"`
		} `json:"SecurityCodeScan"`
		Semgrep struct {
			Istoignore bool `json:"istoignore"`
		} `json:"Semgrep"`
		ShellCheck struct {
			Istoignore bool `json:"istoignore"`
		} `json:"ShellCheck"`
		Sobelow struct {
			Istoignore bool `json:"istoignore"`
		} `json:"Sobelow"`
		TfSec struct {
			Istoignore bool `json:"istoignore"`
		} `json:"TfSec"`
		YarnAudit struct {
			Istoignore bool `json:"istoignore"`
		} `json:"YarnAudit"`
	} `json:"horusecCliToolsConfig"`
	HorusecCliWorkDir struct {
		Go         []interface{} `json:"go"`
		Csharp     []interface{} `json:"csharp"`
		Ruby       []interface{} `json:"ruby"`
		Python     []interface{} `json:"python"`
		Java       []interface{} `json:"java"`
		Kotlin     []interface{} `json:"kotlin"`
		JavaScript []interface{} `json:"javaScript"`
		Leaks      []interface{} `json:"leaks"`
		Hcl        []interface{} `json:"hcl"`
		Php        []interface{} `json:"php"`
		C          []interface{} `json:"c"`
		Yaml       []interface{} `json:"yaml"`
		Generic    []interface{} `json:"generic"`
		Elixir     []interface{} `json:"elixir"`
		Shell      []interface{} `json:"shell"`
		Dart       []interface{} `json:"dart"`
		Nginx      []interface{} `json:"nginx"`
	} `json:"horusecCliWorkDir"`
}
