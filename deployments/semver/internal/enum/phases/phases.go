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

package phases

import (
	"strings"
)

type Phase string

func (p Phase) String() string {
	if p == Release {
		return ""
	}
	return string(p)
}

func (p Phase) IsRelease() bool {
	return p == Release
}

const (
	Alpha            Phase = "alpha"
	Beta             Phase = "beta"
	ReleaseCandidate Phase = "rc"
	Release          Phase = "release"

	Unknown Phase = ""
)

func Values() []Phase {
	return []Phase{
		Alpha,
		Beta,
		ReleaseCandidate,
		Release,
	}
}

func ValueOf(value string) Phase {
	for _, valid := range Values() {
		if IsEqual(value, valid.String()) {
			return valid
		} else if value == "release" {
			return Release
		}
	}

	return Unknown
}

func IsEqual(value, valid string) bool {
	return strings.EqualFold(value, valid)
}

func IndexOf(value Phase) int {
	for i, v := range Values() {
		if v == value {
			return i
		}
	}

	return -1
}
