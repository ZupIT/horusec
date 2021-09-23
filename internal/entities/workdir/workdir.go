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

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/ZupIT/horusec/internal/helpers/messages"
)

type WorkDir struct {
	Go         []string `json:"go"`
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
	Elixir     []string `json:"elixir"`
	Shell      []string `json:"shell"`
	Dart       []string `json:"dart"`
	Nginx      []string `json:"nginx"`
}

//nolint // parse struct is necessary > 15 lines
func NewWorkDir() *WorkDir {
	return &WorkDir{
		Go:         []string{},
		CSharp:     []string{},
		Ruby:       []string{},
		Python:     []string{},
		Java:       []string{},
		Kotlin:     []string{},
		JavaScript: []string{},
		Leaks:      []string{},
		HCL:        []string{},
		PHP:        []string{},
		C:          []string{},
		Yaml:       []string{},
		Generic:    []string{},
		Elixir:     []string{},
		Shell:      []string{},
		Dart:       []string{},
		Nginx:      []string{},
	}
}

func (w *WorkDir) String() string {
	bytes, _ := json.Marshal(w)
	return string(bytes)
}

func (w *WorkDir) ParseInterfaceToStruct(toParse interface{}) *WorkDir {
	if _, ok := toParse.(*WorkDir); ok {
		return toParse.(*WorkDir)
	}
	bytes, err := json.Marshal(toParse)
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorParseStringToWorkDir, err)
		return w
	}
	if err = json.Unmarshal(bytes, &w); err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorParseStringToWorkDir, err)
	}
	return w.setEmptyOrSliceEmptyInNilContent()
}

func (w *WorkDir) Type() string {
	return ""
}

// LanguagePaths returns a map of language and paths that should be analysed.
//
//nolint
func (w *WorkDir) LanguagePaths() map[languages.Language][]string {
	return map[languages.Language][]string{
		languages.Go:         w.Go,
		languages.CSharp:     w.CSharp,
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
		languages.Elixir:     w.Elixir,
		languages.Shell:      w.Shell,
		languages.Dart:       w.Dart,
		languages.Nginx:      w.Nginx,
	}
}

// PathsOfLanguage return the paths of language that should be analyzed.
//
// Return the paths configured if has at least one, otherwise return an
// slice with an empty path string.
func (w *WorkDir) PathsOfLanguage(language languages.Language) []string {
	allPaths := w.LanguagePaths()[language]
	if len(allPaths) > 0 {
		return allPaths
	}

	return []string{""}
}

//nolint // validation is necessary > 5 conditions
func (w *WorkDir) setEmptyOrSliceEmptyInNilContent() *WorkDir {
	if w.Go == nil {
		w.Go = []string{}
	}
	if w.CSharp == nil {
		w.CSharp = []string{}
	}
	if w.Ruby == nil {
		w.Ruby = []string{}
	}
	if w.Python == nil {
		w.Python = []string{}
	}
	if w.Java == nil {
		w.Java = []string{}
	}
	if w.Kotlin == nil {
		w.Kotlin = []string{}
	}
	if w.JavaScript == nil {
		w.JavaScript = []string{}
	}
	if w.Leaks == nil {
		w.Leaks = []string{}
	}
	if w.HCL == nil {
		w.HCL = []string{}
	}
	if w.PHP == nil {
		w.PHP = []string{}
	}
	if w.C == nil {
		w.C = []string{}
	}
	if w.Yaml == nil {
		w.Yaml = []string{}
	}
	if w.Generic == nil {
		w.Generic = []string{}
	}
	if w.Elixir == nil {
		w.Elixir = []string{}
	}
	if w.Shell == nil {
		w.Shell = []string{}
	}
	if w.Dart == nil {
		w.Dart = []string{}
	}
	if w.Nginx == nil {
		w.Nginx = []string{}
	}
	return w
}
