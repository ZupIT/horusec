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
)

type Message struct {
	Message string `json:"message"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Type    string `json:"type"`
}

func (m *Message) GetLine() string {
	return strconv.Itoa(m.Line)
}

func (m *Message) GetColumn() string {
	return strconv.Itoa(m.Column)
}

func (m *Message) IsValidMessage() bool {
	return m.Type == "ERROR" &&
		!strings.Contains(m.Message, "This implies that some PHP code is not scanned by PHPCS")
}
