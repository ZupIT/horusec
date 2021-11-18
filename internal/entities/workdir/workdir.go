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

// WorkDir represents the working directory for each language.
//
// Work directory here means a directory that contains files
// for a specific language.
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

// Default create a new empty work dir.
func Default() *WorkDir {
	return (new(WorkDir).initNilValues())
}

func (w *WorkDir) String() string {
	bytes, _ := json.Marshal(w)
	return string(bytes)
}

// MustParseWorkDir parse a input to WorkDir.
//
// If some error occur an empty work dir will be returned
// and the error will be logged.
func MustParseWorkDir(input map[string]interface{}) *WorkDir {
	wd := new(WorkDir)

	bytes, err := json.Marshal(input)
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorParseStringToWorkDir, err)
		return Default()
	}

	if err := json.Unmarshal(bytes, wd); err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorParseStringToWorkDir, err)
		return Default()
	}

	return wd.initNilValues()
}

// LanguagePaths returns a map of language and paths that should be analysed.
//
// nolint
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

// initNilValues initialize an empty slice for nil values on work dir.
//
// nolint
func (w *WorkDir) initNilValues() *WorkDir {
	if w.Go == nil {
		w.Go = make([]string, 0)
	}
	if w.CSharp == nil {
		w.CSharp = make([]string, 0)
	}
	if w.Ruby == nil {
		w.Ruby = make([]string, 0)
	}
	if w.Python == nil {
		w.Python = make([]string, 0)
	}
	if w.Java == nil {
		w.Java = make([]string, 0)
	}
	if w.Kotlin == nil {
		w.Kotlin = make([]string, 0)
	}
	if w.JavaScript == nil {
		w.JavaScript = make([]string, 0)
	}
	if w.Leaks == nil {
		w.Leaks = make([]string, 0)
	}
	if w.HCL == nil {
		w.HCL = make([]string, 0)
	}
	if w.PHP == nil {
		w.PHP = make([]string, 0)
	}
	if w.C == nil {
		w.C = make([]string, 0)
	}
	if w.Yaml == nil {
		w.Yaml = make([]string, 0)
	}
	if w.Generic == nil {
		w.Generic = make([]string, 0)
	}
	if w.Elixir == nil {
		w.Elixir = make([]string, 0)
	}
	if w.Shell == nil {
		w.Shell = make([]string, 0)
	}
	if w.Dart == nil {
		w.Dart = make([]string, 0)
	}
	if w.Nginx == nil {
		w.Nginx = make([]string, 0)
	}
	return w
}
