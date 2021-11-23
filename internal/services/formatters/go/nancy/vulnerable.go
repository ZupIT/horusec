// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package nancy

import (
	"strings"
)

const indexDependencyVersion = "@"

type nancyAnalysis struct {
	Vulnerable []*nancyVulnerable `json:"vulnerable"`
}

type nancyVulnerable struct {
	Vulnerabilities []*nancyVulnerability `json:"Vulnerabilities"`
	Coordinates     string                `json:"Coordinates"`
}

func (v *nancyVulnerable) getVulnerability() *nancyVulnerability {
	if len(v.Vulnerabilities) > 0 {
		return v.Vulnerabilities[0]
	}

	return nil
}

func (v *nancyVulnerable) getDependency() string {
	dependency := strings.ReplaceAll(v.Coordinates, replaceDependencyText, "")

	index := strings.Index(dependency, indexDependencyVersion)
	if index < 0 {
		return dependency
	}

	return dependency[:index]
}
