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
	NoSec  Severity = "NOSEC"
	Info   Severity = "INFO"
	Low    Severity = "LOW"
	Medium Severity = "MEDIUM"
	High   Severity = "HIGH"
	Audit  Severity = "AUDIT"
)

func (s Severity) ToString() string {
	return string(s)
}

func Map() map[string]Severity {
	return map[string]Severity{
		NoSec.ToString():  NoSec,
		Info.ToString():   Info,
		Low.ToString():    Low,
		Medium.ToString(): Medium,
		High.ToString():   High,
		Audit.ToString():  Audit,
	}
}

func ParseStringToSeverity(content string) Severity {
	return Map()[content]
}
