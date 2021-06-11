package entities

import (
	"strings"
)

type Dependence struct {
	FileName        string           `json:"fileName"`
	FilePath        string           `json:"filePath"`
	Vulnerabilities []*Vulnerability `json:"vulnerabilities"`
}

func (d *Dependence) GetVulnerability() *Vulnerability {
	for _, vulnerability := range d.Vulnerabilities {
		if strings.Contains(vulnerability.Name, "CWE") {
			return vulnerability
		}
	}

	if len(d.Vulnerabilities) >= 1 {
		return d.Vulnerabilities[0]
	}

	return nil
}

func (d *Dependence) GetFile() string {
	index := strings.Index(d.FilePath, "?")
	if index < 0 {
		return d.FilePath
	}

	return d.FilePath[:index]
}
