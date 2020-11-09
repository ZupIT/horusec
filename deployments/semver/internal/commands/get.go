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
