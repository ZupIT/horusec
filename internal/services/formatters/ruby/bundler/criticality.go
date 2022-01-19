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

type bundlerCriticalityType string

const (
	High   bundlerCriticalityType = "High"
	Medium bundlerCriticalityType = "Medium"
	Low    bundlerCriticalityType = "Low"
)

func (c bundlerCriticalityType) String() string {
	return string(c)
}

func getCriticalityTypeByString(criticalityType string) bundlerCriticalityType {
	switch criticalityType {
	case High.String():
		return High
	case Medium.String():
		return Medium
	case Low.String():
		return Low
	}
	return Low
}
