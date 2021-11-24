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

package semgrep

type sgAnalysis struct {
	Results []sgResult `json:"results"`
}

type sgPosition struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type sgResult struct {
	CheckID string     `json:"check_id"`
	Path    string     `json:"path"`
	Start   sgPosition `json:"start"`
	End     sgPosition `json:"end"`
	Extra   sgExtra    `json:"extra"`
}

type sgExtra struct {
	Message  string `json:"message"`
	Severity string `json:"severity"`
	Code     string `json:"lines"`
}
