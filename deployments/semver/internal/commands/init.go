package commands

import (
	"github.com/ZupIT/horusec/deployments/semver/internal/entities"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type InitCommandI interface {
	Handle() error
	Execute(cmd *cobra.Command, args []string) error
	Cmd() *cobra.Command
	Init()
}

func NewInitCommand() InitCommandI {
	cmd := &InitCommand{}
	cmd.Init()
	return cmd
}

type InitCommand struct {
	isForced       bool
	initialRelease entities.Version
	cmd            *cobra.Command
}

func (i *InitCommand) Cmd() *cobra.Command {
	return i.cmd
}

func (i *InitCommand) Execute(cmd *cobra.Command, args []string) error {
	return i.Handle()
}

func (i *InitCommand) Handle() error {
	if i.isForced {
		return viper.WriteConfig()
	}
	return viper.SafeWriteConfig()
}

//nolint
func (i *InitCommand) Init() {
	i.cmd = &cobra.Command{
		Use:     "init",
		Short:   "Initialize semver config",
		Long:    "Initialize required semver config file",
		Example: "semver init [--release v0.1.0] [--rc 1] [--beta 2] [--alpha 3] [--force]",
		RunE:    i.Execute,
	}

	i.cmd.PersistentFlags().Int("alpha", 0, "current alpha version number")
	i.cmd.PersistentFlags().Int("beta", 0, "current beta version number")
	i.cmd.PersistentFlags().Int("rc", 0, "current rc version number")
	i.cmd.PersistentFlags().Var(&i.initialRelease, "release", "release version")
	i.cmd.Flags().BoolVar(&i.isForced, "force", false, "force recreate config file")

	_ = viper.BindPFlag("alpha", i.cmd.PersistentFlags().Lookup("alpha"))
	_ = viper.BindPFlag("beta", i.cmd.PersistentFlags().Lookup("beta"))
	_ = viper.BindPFlag("rc", i.cmd.PersistentFlags().Lookup("rc"))
	_ = viper.BindPFlag("release", i.cmd.PersistentFlags().Lookup("release"))
	viper.SetDefault("alpha", 0)
	viper.SetDefault("beta", 0)
	viper.SetDefault("rc", 0)
	viper.SetDefault("release", "v1.0.0")
}
