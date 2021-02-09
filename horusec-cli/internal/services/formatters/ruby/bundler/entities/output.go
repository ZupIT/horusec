package entities

import (
	"fmt"
	"strings"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
)

type Output struct {
	Name        string
	Version     string
	Advisory    string
	Criticality string
	URL         string
	Title       string
	Solution    string
}

func (o *Output) SetOutputData(output *Output, value string) {
	o.setName(output, value)
	o.setVersion(output, value)
	o.setAdvisory(output, value)
	o.setCriticality(output, value)
	o.setURL(output, value)
	o.setTitle(output, value)
	o.setSolution(output, value)
}

func (o *Output) setName(output *Output, value string) {
	if !strings.Contains(value, ":") {
		output.Name = strings.TrimSpace(value)
	}
}

func (o *Output) setVersion(output *Output, value string) {
	if strings.Contains(value, "Version:") {
		output.Version = strings.TrimSpace(o.getContent(value))
	}
}

func (o *Output) setAdvisory(output *Output, value string) {
	if strings.Contains(value, "Advisory:") {
		output.Advisory = strings.TrimSpace(o.getContent(value))
	}
}

func (o *Output) setCriticality(output *Output, value string) {
	if strings.Contains(value, "Criticality:") {
		output.Criticality = strings.TrimSpace(o.getContent(value))
	}
}

func (o *Output) setURL(output *Output, value string) {
	if strings.Contains(value, "URL:") {
		output.URL = strings.TrimSpace(o.getContent(value))
	}
}

func (o *Output) setTitle(output *Output, value string) {
	if strings.Contains(value, "Title:") {
		output.Title = strings.TrimSpace(o.getContent(value))
	}
}

func (o *Output) setSolution(output *Output, value string) {
	if strings.Contains(value, "Solution:") {
		output.Solution = strings.TrimSpace(o.getContent(value))
	}
}

func (o *Output) getContent(output string) string {
	index := strings.Index(output, ":")
	if index < 0 {
		return ""
	}

	return output[index+1:]
}

func (o *Output) GetSeverity() severity.Severity {
	switch o.Criticality {
	case "High":
		return severity.High

	case "Medium":
		return severity.Medium

	case "Low":
		return severity.Low
	}

	return severity.Unknown
}

func (o *Output) GetDetails() string {
	return fmt.Sprintf("%s (%s - %s) %s (%s - %s)", o.Title, o.Name, o.Version, o.Solution, o.Advisory, o.URL)
}
