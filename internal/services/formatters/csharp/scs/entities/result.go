package entities

import (
	"strconv"
	"strings"
)

type Result struct {
	RuleID    string      `json:"ruleId"`
	Message   Message     `json:"message"`
	Locations []*Location `json:"locations"`
}

func (r *Result) GetLine() string {
	if len(r.Locations) > 0 {
		return strconv.Itoa(r.Locations[0].PhysicalLocation.Region.StartLine)
	}

	return ""
}

func (r *Result) GetColumn() string {
	if len(r.Locations) > 0 {
		return strconv.Itoa(r.Locations[0].PhysicalLocation.Region.StartColumn)
	}

	return ""
}

func (r *Result) GetVulnName() string {
	return r.Message.Text
}

func (r *Result) GetFile() string {
	if len(r.Locations) > 0 {
		return strings.ReplaceAll(r.Locations[0].PhysicalLocation.ArtifactLocation.URI, "file:///src/", "")
	}

	return ""
}
