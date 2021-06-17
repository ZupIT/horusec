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
