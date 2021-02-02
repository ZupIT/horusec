package commands

import "github.com/spf13/cobra"

type ICommand interface {
	Cmd() *cobra.Command
}