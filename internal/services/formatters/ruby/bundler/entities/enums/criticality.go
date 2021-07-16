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

package enums

type CriticalityType string

const (
	High   CriticalityType = "High"
	Medium CriticalityType = "Medium"
	Low    CriticalityType = "Low"
)

func (c CriticalityType) ToString() string {
	return string(c)
}

func GetCriticalityTypeByString(criticalityType string) CriticalityType {
	switch criticalityType {
	case High.ToString():
		return High
	case Medium.ToString():
		return Medium
	case Low.ToString():
		return Low
	}
	return Low
}
