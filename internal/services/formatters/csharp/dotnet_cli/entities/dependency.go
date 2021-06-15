package entities

import (
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
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
	case "Critical":
		return severities.Critical
	case "High":
		return severities.High
	case "Moderate":
		return severities.Medium
	case "Low":
		return severities.Low
	default:
		return severities.Unknown
	}
}
