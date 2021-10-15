package main

import (
	"fmt"
	"github.com/spf13/pflag"
	"os"
	"path/filepath"
	"time"
)

func rootFlags(flags *pflag.FlagSet) {

	rootCmd.PersistentFlags().
		StringVar(
			&logLevel,
			"log-level",
			"info",
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
			&logFilePath,
			"log-file-path", "l",
			filepath.Join(
				os.TempDir(), fmt.Sprintf("horusec-%s.log", time.Now().Format("2006-01-02-15-04-05")),
			),
			`set user defined log file path instead of default`,
		)
	rootCmd.PersistentFlags().
		Bool(
			"is-timeout",
			false,
			`set user defined log file path instead of default`,
		)

	rootCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "Print the configuration")
}
