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

import "github.com/ZupIT/horusec-devkit/pkg/enums/severities"

type Issue struct {
	Findings           []Finding `json:"findings"`
	ID                 int       `json:"id"`
	ModuleName         string    `json:"module_name"`
	VulnerableVersions string    `json:"vulnerable_versions"`
	Severity           string    `json:"severity"`
	Overview           string    `json:"overview"`
}

func (i *Issue) GetSeverity() severities.Severity {
	return i.mapSeverities()[i.Severity]
}

func (i *Issue) mapSeverities() map[string]severities.Severity {
	return map[string]severities.Severity{
		"critical": severities.Critical,
		"high":     severities.High,
		"moderate": severities.Medium,
		"low":      severities.Low,
		"info":     severities.Info,
		"":         severities.Unknown,
	}
}

func (i *Issue) GetVersion() string {
	if len(i.Findings) > 0 {
		return i.Findings[0].Version
	}

	return ""
}
