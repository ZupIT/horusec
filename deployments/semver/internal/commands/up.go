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

type UpVersionCommandI interface {
	Handle(release *entities.Version, phase string) error
	Execute(cmd *cobra.Command, args []string) error
	Cmd() *cobra.Command
	Init()
}

func NewUpVersionCommand() UpVersionCommandI {
	cmd := &UpVersionCommand{}
	cmd.Init()
	return cmd
}

type UpVersionCommand struct {
	cmd *cobra.Command
}

//nolint
func (u *UpVersionCommand) Handle(release *entities.Version, phase string) error {
	if phase == "alpha" || phase == "beta" || phase == "rc" {
		release.Phase = phases.ValueOf(phase)
		release.PatchNumber = viper.GetUint(phase)
		release.PatchNumber++
		viper.Set(phase, release.PatchNumber)
	}

	if phase == "release" && isAlreadyReleased() {
		if isAlreadyReleased() {
			release.Patch++
			viper.Set("release", release.String())
		}
	}

	if phase == "minor" {
		release.Minor++
		release.Patch = 0
		viper.Set("release", release.String())
	}

	if phase == "major" {
		release.Major++
		release.Minor = 0
		release.Patch = 0
		viper.Set("release", release.String())
	}

	if phase == "minor" || phase == "release" || phase == "major" {
		release.PatchNumber = 0
		viper.Set("alpha", 0)
		viper.Set("beta", 0)
		viper.Set("rc", 0)
	}

	fmt.Println(release)

	return viper.WriteConfig()
}

func isAlreadyReleased() bool {
	return viper.GetInt("alpha") == 0 && viper.GetInt("beta") == 0 && viper.GetInt("rc") == 0
}

func (u *UpVersionCommand) Execute(cmd *cobra.Command, args []string) error {
	version, err := entities.NewVersion(viper.GetString("release"))
	if err != nil {
		return fmt.Errorf("failed to load release version: %v", err)
	}

	return u.Handle(version, args[0])
}

func (u *UpVersionCommand) Cmd() *cobra.Command {
	return u.cmd
}

func (u *UpVersionCommand) Init() {
	u.cmd = &cobra.Command{
		Use:       "up",
		Short:     "Increase current version",
		Long:      "Increase the current version based on the give phase (release, rc, beta, alpha)",
		Example:   "semver up alpha",
		RunE:      u.Execute,
		Args:      cobra.ExactValidArgs(1),
		ValidArgs: []string{"alpha", "beta", "rc", "release", "minor", "major"},
	}
}
