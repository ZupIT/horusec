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

package tfsec

import (
	"fmt"
	"strconv"

	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
)

type tfsecResult struct {
	RuleID      string   `json:"rule_id"`
	Link        string   `json:"link"`
	Location    Location `json:"location"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
}

func (r *tfsecResult) getDetails() string {
	return r.RuleID + " -> [" + r.Description + "]"
}

func (r *tfsecResult) getStartLine() string {
	return strconv.Itoa(r.Location.StartLine)
}

func (r *tfsecResult) getCode() string {
	return fmt.Sprintf("code beetween line %d and %d.", r.Location.StartLine, r.Location.EndLine)
}

func (r *tfsecResult) getFilename() string {
	return r.Location.Filename
}

// getSeverity this func will get the TfSec severity and parse to the Horusec severity. TfSec can return the following
// severities: CRITICAL, HIGH, MEDIUM, LOW and NONE which is represented by an empty string.
func (r *tfsecResult) getSeverity() severities.Severity {
	if r.Severity == "" {
		return severities.Unknown
	}

	return severities.Severity(r.Severity)
}
