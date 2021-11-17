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

package customimages_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	customimages "github.com/ZupIT/horusec/internal/entities/custom_images"
)

func TestNewCustomImages(t *testing.T) {
	t.Run("Should return 12 custom images", func(t *testing.T) {
		assert.Equal(t, 12, len(customimages.Default()))
	})

	t.Run("Should return empty image for all languages as default", func(t *testing.T) {
		images := customimages.Default()
		for lang, image := range images {
			assert.Empty(t, image, "Expected empty default image for %s", lang)
		}
	})
}

func TestMustParseCustomImages(t *testing.T) {
	testcases := []struct {
		name     string
		input    map[string]interface{}
		expected customimages.CustomImages
	}{
		{
			name: "Should parse valid custom images",
			input: map[string]interface{}{
				"go":         "custom/image",
				"csharp":     "custom/image",
				"dart":       "custom/image",
				"ruby":       "custom/image",
				"python":     "custom/image",
				"java":       "custom/image",
				"kotlin":     "custom/image",
				"javascript": "custom/image",
				"typescript": "custom/image",
				"leaks":      "custom/image",
				"hcl":        "custom/image",
				"c":          "custom/image",
				"php":        "custom/image",
				"html":       "custom/image",
				"generic":    "custom/image",
				"yaml":       "custom/image",
				"elixir":     "custom/image",
				"shell":      "custom/image",
				"nginx":      "custom/image",
				"swift":      "custom/image",
			},
			expected: customimages.CustomImages{
				languages.Go:         "custom/image",
				languages.CSharp:     "custom/image",
				languages.Dart:       "custom/image",
				languages.Ruby:       "custom/image",
				languages.Python:     "custom/image",
				languages.Java:       "custom/image",
				languages.Kotlin:     "custom/image",
				languages.Javascript: "custom/image",
				languages.Typescript: "custom/image",
				languages.Leaks:      "custom/image",
				languages.HCL:        "custom/image",
				languages.C:          "custom/image",
				languages.PHP:        "custom/image",
				languages.HTML:       "custom/image",
				languages.Generic:    "custom/image",
				languages.Yaml:       "custom/image",
				languages.Elixir:     "custom/image",
				languages.Shell:      "custom/image",
				languages.Nginx:      "custom/image",
				languages.Swift:      "custom/image",
			},
		},
		{
			name: "Should return default values using invalid schema",
			input: map[string]interface{}{
				"go": map[string]interface{}{
					"invalid": "schema",
				},
			},
			expected: customimages.Default(),
		},
		{
			name: "Should return default values using invalid language",
			input: map[string]interface{}{
				"invalid": "custom/image",
			},
			expected: customimages.Default(),
		},
	}

	logger.LogSetOutput(io.Discard)
	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			images := customimages.MustParseCustomImages(tt.input)

			assert.Equal(t, tt.expected, images)
		})
	}
}
