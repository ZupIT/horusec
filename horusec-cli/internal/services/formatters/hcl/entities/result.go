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

package entities

import (
	"fmt"
	"strconv"
)

type Result struct {
	RuleID      string   `json:"rule_id"`
	Link        string   `json:"link"`
	Location    Location `json:"location"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
}

func (r *Result) GetDetails() string {
	return r.RuleID + " -> [" + r.Description + "]"
}

func (r *Result) GetStartLine() string {
	return strconv.Itoa(r.Location.StartLine)
}

func (r *Result) GetCode() string {
	return fmt.Sprintf("code beetween line %d and %d.", r.Location.StartLine, r.Location.EndLine)
}

func (r *Result) GetFilename() string {
	return r.Location.Filename
}
