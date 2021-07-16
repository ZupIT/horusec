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

package entities

import (
	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
)

type Result struct {
	Code            string                `json:"code"`
	FileName        string                `json:"filename"`
	IssueConfidence confidence.Confidence `json:"issue_confidence"`
	IssueSeverity   severities.Severity   `json:"issue_severity"`
	IssueText       string                `json:"issue_text"`
	LineNumber      int                   `json:"line_number"`
	LineRange       []int                 `json:"line_range"`
	MoreInfo        string                `json:"more_info"`
	TestID          string                `json:"test_id"`
	TestName        string                `json:"test_name"`
}

func (r *Result) GetFile() string {
	if r.FileName != "" && r.FileName[0:2] == "./" {
		return r.FileName[2:]
	}

	return r.FileName
}
