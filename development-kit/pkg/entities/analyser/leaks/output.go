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

package leaks

type Issue struct {
	Line          string `json:"line"`
	Offender      string `json:"offender"`
	Commit        string `json:"commit"`
	Repo          string `json:"repo"`
	Rule          string `json:"rule"`
	CommitMessage string `json:"commitMessage"`
	Author        string `json:"author"`
	Email         string `json:"email"`
	File          string `json:"file"`
	Date          string `json:"date"`
	Tags          string `json:"tags"`
}
