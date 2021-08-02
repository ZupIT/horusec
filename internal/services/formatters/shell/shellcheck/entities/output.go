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

import "strconv"

type Output struct {
	File      string      `json:"file"`
	Line      int         `json:"line"`
	EndLine   int         `json:"endLine"`
	Column    int         `json:"column"`
	EndColumn int         `json:"endColumn"`
	Level     string      `json:"level"`
	Code      int         `json:"code"`
	Message   string      `json:"message"`
	Fix       interface{} `json:"fix"`
}

func (o *Output) GetLine() string {
	return strconv.Itoa(o.Line)
}

func (o *Output) GetColumn() string {
	return strconv.Itoa(o.Column)
}
