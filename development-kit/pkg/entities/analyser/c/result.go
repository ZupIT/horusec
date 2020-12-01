package c

import (
	"fmt"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"strconv"
	"strings"
)

type Result struct {
	File       string `json:"file"`
	Line       string `json:"line"`
	Column     string `json:"column"`
	Level      string `json:"level"`
	Warning    string `json:"warning"`
	Suggestion string `json:"suggestion"`
	Note       string `json:"note"`
	Context    string `json:"context"`
}

func (r *Result) GetDetails() string {
	return fmt.Sprintf("%s %s %s", r.Warning, r.Suggestion, r.Note)
}

func (r *Result) GetSeverity() severity.Severity {
	level, _ := strconv.Atoi(r.Level)
	if level <= 2 {
		return severity.Low
	}

	if level >= 3 && level <= 4 {
		return severity.Medium
	}

	return severity.High
}

func (r *Result) GetFilename() string {
	return strings.ReplaceAll(r.File, "./", "")
}
