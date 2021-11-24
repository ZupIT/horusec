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

package dotnetcli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
)

const (
	indexDependencyName        = 0
	indexDependencyVersion     = 2
	indexDependencySeverity    = 3
	indexDependencyDescription = 4
	critical                   = "Critical"
	high                       = "High"
	moderate                   = "Moderate"
	low                        = "Low"
	solutionNotFound           = "A project or solution file could not be found"
	autoReferencedPacket       = "(A)"
	separator                  = ">"
	// nolint: lll
	dependencyDescription = "A possible vulnerable dependency was found, please checkout the following url for more information (%s)."
)

var ErrorSolutionNotFound = errors.New("{DOTNET CLI} solution file not found")

type dotnetDependency struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

func (d *dotnetDependency) setName(name string) {
	d.Name = strings.TrimSpace(name)
}

func (d *dotnetDependency) setVersion(version string) {
	d.Version = strings.TrimSpace(version)
}

func (d *dotnetDependency) setDescription(description string) {
	d.Description = strings.TrimSpace(description)
}

func (d *dotnetDependency) setSeverity(severity string) {
	severity = strings.ReplaceAll(severity, "\u001B[31m", "")
	severity = strings.ReplaceAll(severity, "\u001B[33m", "")
	d.Severity = strings.TrimSpace(severity)
}

//nolint:funlen
func (d *dotnetDependency) getSeverity() severities.Severity {
	switch d.Severity {
	case critical:
		return severities.Critical
	case high:
		return severities.High
	case moderate:
		return severities.Medium
	case low:
		return severities.Low
	default:
		return severities.Unknown
	}
}

func (d *dotnetDependency) getDescription() string {
	return fmt.Sprintf(dependencyDescription, d.Description)
}
