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

package bundler

import (
	"fmt"
	"strings"

	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
)

type bundlerOutput struct {
	Name        string
	Version     string
	Advisory    string
	Criticality bundlerCriticalityType
	URL         string
	Title       string
	Solution    string
}

func (o *bundlerOutput) setOutputData(output *bundlerOutput, value string) {
	o.setName(output, value)
	o.setVersion(output, value)
	o.setAdvisory(output, value)
	o.setCriticality(output, value)
	o.setURL(output, value)
	o.setTitle(output, value)
	o.setSolution(output, value)
}

func (o *bundlerOutput) setName(output *bundlerOutput, value string) {
	if !strings.Contains(value, ":") {
		output.Name = strings.TrimSpace(value)
	}
}

func (o *bundlerOutput) setVersion(output *bundlerOutput, value string) {
	if strings.Contains(value, "Version:") {
		output.Version = strings.TrimSpace(o.getContent(value))
	}
}

func (o *bundlerOutput) setAdvisory(output *bundlerOutput, value string) {
	if strings.Contains(value, "Advisory:") {
		output.Advisory = strings.TrimSpace(o.getContent(value))
	}
}

func (o *bundlerOutput) setCriticality(output *bundlerOutput, value string) {
	if strings.Contains(value, "Criticality:") {
		output.Criticality = getCriticalityTypeByString(strings.TrimSpace(o.getContent(value)))
	}
}

func (o *bundlerOutput) setURL(output *bundlerOutput, value string) {
	if strings.Contains(value, "URL:") {
		output.URL = strings.TrimSpace(o.getContent(value))
	}
}

func (o *bundlerOutput) setTitle(output *bundlerOutput, value string) {
	if strings.Contains(value, "Title:") {
		output.Title = strings.TrimSpace(o.getContent(value))
	}
}

func (o *bundlerOutput) setSolution(output *bundlerOutput, value string) {
	if strings.Contains(value, "Solution:") {
		output.Solution = strings.TrimSpace(o.getContent(value))
	}
}

func (o *bundlerOutput) getContent(output string) string {
	index := strings.Index(output, ":")
	if index < 0 {
		return ""
	}

	return output[index+1:]
}

func (o *bundlerOutput) getSeverity() severities.Severity {
	switch o.Criticality {
	case High:
		return severities.High
	case Medium:
		return severities.Medium
	case Low:
		return severities.Low
	}

	return severities.Unknown
}

func (o *bundlerOutput) getDetails() string {
	return fmt.Sprintf("%s (%s - %s) %s (%s - %s)", o.Title, o.Name, o.Version, o.Solution, o.Advisory, o.URL)
}
