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

type Analysis struct {
	Runs []*Run `json:"runs"`
}

func (a *Analysis) GetRun() *Run {
	if len(a.Runs) > 0 {
		return a.Runs[0]
	}

	return nil
}

func (a *Analysis) MapVulnerabilitiesByID() map[string]*Rule {
	vulnMap := map[string]*Rule{}

	for _, rule := range a.GetRun().Tool.Driver.Rules {
		vulnMap[rule.ID] = rule
	}

	return vulnMap
}
