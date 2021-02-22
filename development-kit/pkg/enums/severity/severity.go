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

package severity

type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
	Unknown  Severity = "UNKNOWN"
	Info     Severity = "INFO"
)

func (s Severity) ToString() string {
	return string(s)
}

func Map() map[string]Severity {
	return map[string]Severity{
		Critical.ToString(): Critical,
		High.ToString():     High,
		Medium.ToString():   Medium,
		Low.ToString():      Low,
		Unknown.ToString():  Unknown,
		Info.ToString():     Info,
	}
}

func ParseStringToSeverity(content string) Severity {
	return Map()[content]
}
