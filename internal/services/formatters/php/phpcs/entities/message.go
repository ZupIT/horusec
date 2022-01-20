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

	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
)

const (
	MessageError   = "ERROR"
	MessageWarning = "WARNING"
)

const (
	SeverityLevelLow      = 2
	SeverityLevelMedium   = 3
	SeverityLevelHigh     = 4
	SeverityLevelCritical = 5
)

type Message struct {
	Severity int    `json:"severity"`
	Source   string `json:"source"`
	Message  string `json:"message"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Type     string `json:"type"`
}

func (m *Message) GetLine() string {
	return strconv.Itoa(m.Line)
}

func (m *Message) GetColumn() string {
	return strconv.Itoa(m.Column)
}

func (m *Message) IsAllowedMessage() bool {
	return m.isWarningMessage() || m.isErrorMessage()
}

func (m *Message) isErrorMessage() bool {
	return m.Type == MessageError
}

func (m *Message) isWarningMessage() bool {
	return m.Type == MessageWarning
}

func (m *Message) IsNotFailedToScan() bool {
	return !strings.Contains(strings.ToLower(m.Message),
		"this implies that some php code is not scanned by phpcs")
}

// nolint:funlen,gocyclo // method of validation
func (m *Message) GetSeverity() severities.Severity {
	switch {
	case m.isWarningMessage() && m.Severity >= SeverityLevelCritical:
		return severities.Info
	case m.Severity < SeverityLevelLow:
		return severities.Low
	case m.Severity >= SeverityLevelLow && m.Severity <= SeverityLevelMedium:
		return severities.Medium
	case m.Severity == SeverityLevelHigh:
		return severities.High
	case m.Severity >= SeverityLevelCritical:
		return severities.Critical
	default:
		return severities.Unknown
	}
}
