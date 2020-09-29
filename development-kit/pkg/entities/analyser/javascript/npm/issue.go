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

package npm

import "github.com/ZupIT/horusec/development-kit/pkg/enums/severity"

type Issue struct {
	Findings           []Finding `json:"findings"`
	ID                 int       `json:"id"`
	ModuleName         string    `json:"module_name"`
	VulnerableVersions string    `json:"vulnerable_versions"`
	Severity           string    `json:"severity"`
	Overview           string    `json:"overview"`
}

func (i *Issue) GetSeverity() severity.Severity {
	if i.IsLowSeverity() {
		return severity.Low
	}

	if i.IsMediumSeverity() {
		return severity.Medium
	}

	if i.IsHighSeverity() {
		return severity.High
	}

	return severity.NoSec
}

func (i *Issue) IsLowSeverity() bool {
	return i.Severity == "low" || i.Severity == "info"
}

func (i *Issue) IsMediumSeverity() bool {
	return i.Severity == "moderate"
}

func (i *Issue) IsHighSeverity() bool {
	return i.Severity == "high" || i.Severity == "critical"
}

func (i *Issue) GetVersion() string {
	if len(i.Findings) > 0 {
		return i.Findings[0].Version
	}

	return ""
}
