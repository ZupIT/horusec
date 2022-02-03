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

package brakeman

import (
	"fmt"
	"strconv"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
)

const (
	confidenceHigh   = "High"
	confidenceMedium = "Medium"
)

type brakemanOutput struct {
	Warnings []warning `json:"warnings"`
}

type warning struct {
	Type        string `json:"warning_type"`
	WarningCode int    `json:"warning_code"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Details     string `json:"link"`
	Confidence  string `json:"confidence"`
}

func (o *warning) getDetails() string {
	return fmt.Sprintf("%s %s", o.Details, o.Message)
}

func (o *warning) getSeverity() severities.Severity {
	if o.Confidence == confidenceHigh {
		return severities.High
	}

	if o.Confidence == confidenceMedium {
		return severities.Medium
	}

	return severities.Low
}

func (o *warning) getConfidence() confidence.Confidence {
	if o.Confidence == confidenceHigh {
		return confidence.High
	}

	if o.Confidence == confidenceMedium {
		return confidence.Medium
	}

	return confidence.Low
}

func (o *warning) getLine() string {
	return strconv.Itoa(o.Line)
}
