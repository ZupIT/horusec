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

package npmaudit

import "github.com/ZupIT/horusec-devkit/pkg/enums/severities"

type npmOutput struct {
	Advisories map[string]npmIssue `json:"advisories"`
	Metadata   npmMetadata         `json:"metadata"`
}

type npmMetadata struct {
	Vulnerabilities npmVulnerabilities `json:"vulnerabilities"`
}

type npmVulnerabilities struct {
	Info     int `json:"info"`
	Low      int `json:"low"`
	Moderate int `json:"moderate"`
	High     int `json:"high"`
	Critical int `json:"critical"`
}

type npmFinding struct {
	Version string `json:"version"`
}

type npmIssue struct {
	Findings           []npmFinding `json:"findings"`
	ID                 int          `json:"id"`
	ModuleName         string       `json:"module_name"`
	VulnerableVersions string       `json:"vulnerable_versions"`
	Severity           string       `json:"severity"`
	Overview           string       `json:"overview"`
}

func (i *npmIssue) getSeverity() severities.Severity {
	return i.mapSeverities()[i.Severity]
}

func (i *npmIssue) mapSeverities() map[string]severities.Severity {
	return map[string]severities.Severity{
		"critical": severities.Critical,
		"high":     severities.High,
		"moderate": severities.Medium,
		"low":      severities.Low,
		"info":     severities.Info,
		"":         severities.Unknown,
	}
}

func (i *npmIssue) getVersion() string {
	if len(i.Findings) > 0 {
		return i.Findings[0].Version
	}

	return ""
}
