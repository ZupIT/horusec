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

package workdir_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec/internal/entities/workdir"
)

func TestDefaultReturnEmptyWorkDir(t *testing.T) {
	wd := workdir.Default()

	assert.Empty(t, wd.Go)
	assert.Empty(t, wd.CSharp)
	assert.Empty(t, wd.Ruby)
	assert.Empty(t, wd.Python)
	assert.Empty(t, wd.Java)
	assert.Empty(t, wd.Kotlin)
	assert.Empty(t, wd.JavaScript)
	assert.Empty(t, wd.Leaks)
	assert.Empty(t, wd.HCL)
	assert.Empty(t, wd.PHP)
	assert.Empty(t, wd.C)
	assert.Empty(t, wd.Yaml)
	assert.Empty(t, wd.Generic)
	assert.Empty(t, wd.Elixir)
	assert.Empty(t, wd.Shell)
	assert.Empty(t, wd.Dart)
	assert.Empty(t, wd.Nginx)
}

func TestMustParseWorkDir(t *testing.T) {
	testcases := []struct {
		name     string
		input    map[string]interface{}
		expected *workdir.WorkDir
	}{
		{
			name: "Should successfully parse work dir",
			input: map[string]interface{}{
				"go": []string{
					"some/random/path",
				},
				"csharp": []string{},
				"dart": []string{
					"other/random/path",
				},
			},
			expected: &workdir.WorkDir{
				Go: []string{
					"some/random/path",
				},
				CSharp:     make([]string, 0),
				Ruby:       make([]string, 0),
				Python:     make([]string, 0),
				Java:       make([]string, 0),
				Kotlin:     make([]string, 0),
				JavaScript: make([]string, 0),
				Leaks:      make([]string, 0),
				HCL:        make([]string, 0),
				PHP:        make([]string, 0),
				C:          make([]string, 0),
				Yaml:       make([]string, 0),
				Generic:    make([]string, 0),
				Elixir:     make([]string, 0),
				Shell:      make([]string, 0),
				Nginx:      make([]string, 0),
				Dart: []string{
					"other/random/path",
				},
			},
		},
		{
			name: "Should fail on parse invalid work dir and return default",
			input: map[string]interface{}{
				"go": "invalid type value",
			},
			expected: workdir.Default(),
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			wd := workdir.MustParseWorkDir(tt.input)

			assert.Equal(t, tt.expected, wd)
		})
	}
}

func TestLanguagePaths(t *testing.T) {
	wd := workdir.MustParseWorkDir(map[string]interface{}{
		"go":     []string{"some/random/path"},
		"csharp": []string{"other/path"},
	})

	expected := map[languages.Language][]string{
		languages.Go:         {"some/random/path"},
		languages.CSharp:     {"other/path"},
		languages.Ruby:       make([]string, 0),
		languages.Python:     make([]string, 0),
		languages.Java:       make([]string, 0),
		languages.Kotlin:     make([]string, 0),
		languages.Javascript: make([]string, 0),
		languages.Leaks:      make([]string, 0),
		languages.HCL:        make([]string, 0),
		languages.Generic:    make([]string, 0),
		languages.PHP:        make([]string, 0),
		languages.C:          make([]string, 0),
		languages.Yaml:       make([]string, 0),
		languages.Elixir:     make([]string, 0),
		languages.Shell:      make([]string, 0),
		languages.Dart:       make([]string, 0),
		languages.Nginx:      make([]string, 0),
	}

	assert.Equal(t, expected, wd.LanguagePaths())
}

func TestPathsOfLanguage(t *testing.T) {
	goPaths := []string{"some/random/path"}
	wd := workdir.MustParseWorkDir(map[string]interface{}{
		"go": goPaths,
	})

	assert.Equal(
		t,
		goPaths,
		wd.PathsOfLanguage(languages.Go),
		"Expected equal paths to a language that have a custom work dir",
	)

	assert.Equal(
		t,
		[]string{""},
		wd.PathsOfLanguage(languages.Java),
		"Expected a slice with an empty path for a language that does not have custom work dir",
	)
}

func TestString(t *testing.T) {
	wd := workdir.Default()

	expected := `
{
  "go": [],
  "csharp": [],
  "ruby": [],
  "python": [],
  "java": [],
  "kotlin": [],
  "javaScript": [],
  "leaks": [],
  "hcl": [],
  "php": [],
  "c": [],
  "yaml": [],
  "generic": [],
  "elixir": [],
  "shell": [],
  "dart": [],
  "nginx": []
}
	`

	assert.JSONEq(t, expected, wd.String())
}
