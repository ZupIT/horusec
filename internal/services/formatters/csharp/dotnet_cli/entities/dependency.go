package entities

import (
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"

	"github.com/ZupIT/horusec/internal/services/formatters/csharp/dotnet_cli/enums"
)

type Dependency struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

func (d *Dependency) SetName(name string) {
	d.Name = strings.TrimSpace(name)
}

func (d *Dependency) SetVersion(version string) {
	d.Version = strings.TrimSpace(version)
}

func (d *Dependency) SetDescription(description string) {
	d.Description = strings.TrimSpace(description)
}

func (d *Dependency) SetSeverity(severity string) {
	severity = strings.ReplaceAll(severity, "\u001B[31m", "")
	severity = strings.ReplaceAll(severity, "\u001B[33m", "")
	d.Severity = strings.TrimSpace(severity)
}

//nolint:funlen // need to have more than 11 statements
func (d *Dependency) GetSeverity() severities.Severity {
	switch d.Severity {
	case enums.Critical:
		return severities.Critical
	case enums.High:
		return severities.High
	case enums.Moderate:
		return severities.Medium
	case enums.Low:
		return severities.Low
	default:
		return severities.Unknown
	}
}
