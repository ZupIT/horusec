package commands

import (
	"fmt"
	"github.com/ZupIT/horusec/deployments/semver/internal/entities"
	"github.com/ZupIT/horusec/deployments/semver/internal/enum/phases"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type GetCommandI interface {
	Handle(version *entities.Version, phase string) error
	Execute(cmd *cobra.Command, args []string) error
	Cmd() *cobra.Command
	Init()
}

func NewGetCommand() GetCommandI {
	cmd := &GetCommand{}
	cmd.Init()
	return cmd
}

type GetCommand struct {
	cmd *cobra.Command
}

func (g *GetCommand) Cmd() *cobra.Command {
	return g.cmd
}

func (g *GetCommand) Execute(cmd *cobra.Command, args []string) error {
	version, err := entities.NewVersion(viper.GetString("release"))
	if err != nil {
		return fmt.Errorf("failed to load release version: %v", err)
	}

	return g.Handle(version, args[0])
}

//nolint
func (g *GetCommand) Handle(version *entities.Version, phase string) error {
	if phase != "release" {
		version.PatchNumber = viper.GetUint(phase)
	}

	version.Phase = phases.ValueOf(phase)
	fmt.Println(version.String())

	return nil
}

func (g *GetCommand) Init() {
	g.cmd = &cobra.Command{
		Use:       "get",
		Short:     "Returns the current version number",
		Long:      "Returns the current version number to the given phase",
		Example:   "semver get release",
		ValidArgs: []string{"alpha", "beta", "rc", "release"},
		Args:      cobra.ExactValidArgs(1),
		RunE:      g.Execute,
	}
}
