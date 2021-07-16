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
	"fmt"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/enums/confidence"
	"github.com/ZupIT/horusec/internal/services/formatters/ruby/bundler/entities/enums"

	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
)

type Output struct {
	Name        string
	Version     string
	Advisory    string
	Criticality enums.CriticalityType
	URL         string
	Title       string
	Solution    string
}

func (o *Output) SetOutputData(output *Output, value string) {
	o.setName(output, value)
	o.setVersion(output, value)
	o.setAdvisory(output, value)
	o.setCriticality(output, value)
	o.setURL(output, value)
	o.setTitle(output, value)
	o.setSolution(output, value)
}

func (o *Output) setName(output *Output, value string) {
	if !strings.Contains(value, ":") {
		output.Name = strings.TrimSpace(value)
	}
}

func (o *Output) setVersion(output *Output, value string) {
	if strings.Contains(value, "Version:") {
		output.Version = strings.TrimSpace(o.getContent(value))
	}
}

func (o *Output) setAdvisory(output *Output, value string) {
	if strings.Contains(value, "Advisory:") {
		output.Advisory = strings.TrimSpace(o.getContent(value))
	}
}

func (o *Output) setCriticality(output *Output, value string) {
	if strings.Contains(value, "Criticality:") {
		output.Criticality = enums.GetCriticalityTypeByString(strings.TrimSpace(o.getContent(value)))
	}
}

func (o *Output) setURL(output *Output, value string) {
	if strings.Contains(value, "URL:") {
		output.URL = strings.TrimSpace(o.getContent(value))
	}
}

func (o *Output) setTitle(output *Output, value string) {
	if strings.Contains(value, "Title:") {
		output.Title = strings.TrimSpace(o.getContent(value))
	}
}

func (o *Output) setSolution(output *Output, value string) {
	if strings.Contains(value, "Solution:") {
		output.Solution = strings.TrimSpace(o.getContent(value))
	}
}

func (o *Output) getContent(output string) string {
	index := strings.Index(output, ":")
	if index < 0 {
		return ""
	}

	return output[index+1:]
}

func (o *Output) GetSeverity() severities.Severity {
	switch o.Criticality {
	case enums.High:
		return severities.High
	case enums.Medium:
		return severities.Medium
	case enums.Low:
		return severities.Low
	}

	return severities.Unknown
}

func (o *Output) GetConfidence() confidence.Confidence {
	switch o.Criticality {
	case enums.High:
		return confidence.High
	case enums.Medium:
		return confidence.Medium
	case enums.Low:
		return confidence.Low
	}

	return confidence.Low
}

func (o *Output) GetDetails() string {
	return fmt.Sprintf("%s (%s - %s) %s (%s - %s)", o.Title, o.Name, o.Version, o.Solution, o.Advisory, o.URL)
}
