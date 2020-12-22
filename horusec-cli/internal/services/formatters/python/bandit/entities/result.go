package entities

import "github.com/ZupIT/horusec/development-kit/pkg/enums/severity"

type Result struct {
	Code            string            `json:"code"`
	FileName        string            `json:"filename"`
	IssueConfidence string            `json:"issue_confidence"`
	IssueSeverity   severity.Severity `json:"issue_severity"`
	IssueText       string            `json:"issue_text"`
	LineNumber      int               `json:"line_number"`
	LineRange       []int             `json:"line_range"`
	MoreInfo        string            `json:"more_info"`
	TestID          string            `json:"test_id"`
	TestName        string            `json:"test_name"`
}

func (r *Result) GetFile() string {
	if r.FileName != "" && r.FileName[0:2] == "./" {
		return r.FileName[2:]
	}

	return r.FileName
}
