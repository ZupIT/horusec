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

package ruby

import (
	"fmt"
	"strconv"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
)

type Warning struct {
	Type       string `json:"warning_type"`
	Code       string `json:"code"`
	Message    string `json:"message"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	Details    string `json:"link"`
	Confidence string `json:"confidence"`
}

const (
	confidenceHigh   = "High"
	confidenceMedium = "Medium"
	confidenceLow    = "Low"
)

func (o *Warning) GetDetails() string {
	return fmt.Sprintf("%s %s", o.Details, o.Message)
}

func (o *Warning) GetSeverity() severity.Severity {
	if o.Confidence == confidenceHigh {
		return severity.High
	}
	if o.Confidence == confidenceMedium {
		return severity.Medium
	}
	if o.Confidence == confidenceLow {
		return severity.Low
	}
	return severity.NoSec
}

func (o *Warning) GetLine() string {
	return strconv.Itoa(o.Line)
}
