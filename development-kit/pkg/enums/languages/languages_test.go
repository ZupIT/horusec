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

package languages

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestToString(t *testing.T) {
	t.Run("should success parse to string", func(t *testing.T) {
		assert.NotEmpty(t, CSharp.ToString())
	})
}

func TestMapEnableLanguages(t *testing.T) {
	t.Run("should map enable languages", func(t *testing.T) {
		assert.Len(t, CSharp.MapEnableLanguages(), 12)
	})
}

func TestParseStringToLanguage(t *testing.T) {
	t.Run("should get language from string", func(t *testing.T) {
		lang := ParseStringToLanguage("Go")
		assert.Equal(t, Go, lang)

		lang = ParseStringToLanguage("test")
		assert.Equal(t, Unknown, lang)
	})
}

func TestSupportedLanguages(t *testing.T) {
	t.Run("should return supported languages", func(t *testing.T) {
		assert.Len(t, SupportedLanguages(), 13)
	})
}
