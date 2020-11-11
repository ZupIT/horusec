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

package entities

import (
	"errors"
	"fmt"
	"github.com/ZupIT/horusec/deployments/semver/internal/enum/phases"
	"github.com/ZupIT/horusec/deployments/semver/internal/utils/str"
	"regexp"
)

type Version struct {
	Prefix      string
	Major       uint
	Minor       uint
	Patch       uint
	Phase       phases.Phase
	PatchNumber uint
}

func NewVersion(v string) (*Version, error) {
	version := &Version{}
	err := version.Set(v)
	if err != nil {
		return nil, err
	}
	return version, nil
}

func (v *Version) String() string {
	if v.Phase.IsRelease() {
		return fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
	}
	return fmt.Sprintf("v%d.%d.%d-%s.%d", v.Major, v.Minor, v.Patch, v.Phase, v.PatchNumber)
}

//nolint
func (v *Version) Set(value string) error {
	tagPattern, _ := regexp.Compile(`^(v?)(\d+)\.(\d+)\.(\d+)((-(alpha|beta|rc))\.(\d+))?$`)
	if !tagPattern.MatchString(value) {
		return errors.New("invalid version format")
	}
	parts := tagPattern.FindStringSubmatch(value)
	v.Prefix = parts[1]
	v.Major = str.ParseUIntOrDefault(parts[2])
	v.Minor = str.ParseUIntOrDefault(parts[3])
	v.Patch = str.ParseUIntOrDefault(parts[4])
	v.Phase = phases.ValueOf(parts[7])
	v.PatchNumber = str.ParseUIntOrDefault(parts[8])
	return nil
}

func (v *Version) Type() string {
	return "version"
}
