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

package workdir

import (
	"encoding/json"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/languages"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-cli/internal/helpers/messages"
)

type WorkDir struct {
	Go         []string `json:"go"`
	NetCore    []string `json:"netCore"`
	CSharp     []string `json:"csharp"`
	Ruby       []string `json:"ruby"`
	Python     []string `json:"python"`
	Java       []string `json:"java"`
	Kotlin     []string `json:"kotlin"`
	JavaScript []string `json:"javaScript"`
	Leaks      []string `json:"leaks"`
	HCL        []string `json:"hcl"`
	PHP        []string `json:"php"`
	C          []string `json:"c"`
	Yaml       []string `json:"yaml"`
	Generic    []string `json:"generic"`
}

func (w *WorkDir) String() string {
	bytes, _ := json.Marshal(w)
	return string(bytes)
}

func (w *WorkDir) ParseInterfaceToStruct(toParse interface{}) {
	bytes, err := json.Marshal(toParse)
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorParseStringToWorkDir, err, logger.ErrorLevel)
		return
	}

	err = json.Unmarshal(bytes, &w)
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorParseStringToWorkDir, err, logger.ErrorLevel)
	}
}

func (w *WorkDir) Type() string {
	return ""
}

//nolint
func (w *WorkDir) Map() map[languages.Language][]string {
	var cSharp []string
	cSharp = append(cSharp, w.NetCore...)
	cSharp = append(cSharp, w.CSharp...)
	return map[languages.Language][]string{
		languages.Go:         w.Go,
		languages.CSharp:     cSharp,
		languages.Ruby:       w.Ruby,
		languages.Python:     w.Python,
		languages.Java:       w.Java,
		languages.Kotlin:     w.Kotlin,
		languages.Javascript: w.JavaScript,
		languages.Leaks:      w.Leaks,
		languages.HCL:        w.HCL,
		languages.Generic:    w.Generic,
		languages.PHP:        w.PHP,
		languages.C:          w.C,
		languages.Yaml:       w.Yaml,
	}
}

func (w *WorkDir) GetArrayByLanguage(language languages.Language) []string {
	result := w.Map()[language]
	if len(result) > 0 {
		return result
	}

	return []string{""}
}
