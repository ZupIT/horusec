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

package customimages

import (
	"encoding/json"
	"fmt"

	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/utils/logger"
	"github.com/ZupIT/horusec/internal/enums/images"
	"github.com/ZupIT/horusec/internal/helpers/messages"
)

// CustomImages is a map of language to a custom image.
//
// The custom image value can be empty.
type CustomImages map[languages.Language]string

// MarshalJSON implements json.Marshaler interface.
//
// Note that we only implement this interface to get the same
// json representation of custom images that is used config file.
// On config file we use all keys in lower case and the const values
// from languages package use language names in CamelCase, so, when we
// print the custom images on debug logging we get a different result from
// config file, what can cause doubts.
//
// A better approach would be use always the language name as declared on
// languages package, but changing this now will introduce breaking changes.
// So we should centralize these castings only in this package and let the
// others not worry about it.
//
// nolint: funlen
func (c CustomImages) MarshalJSON() ([]byte, error) {
	if len(c) == 0 {
		return []byte("null"), nil
	}

	// TODO(matheus): This method should be removed from Language type.
	// A better approach would convert to a public function from languages
	// package.
	enabledLanguages := languages.Generic.MapLanguagesEnableInCLI()

	result := make(map[string]string, len(c))

	for language, image := range c {
		if lang, exists := enabledLanguages[language]; exists {
			result[lang] = image
		}
	}

	return json.Marshal(result)
}

// Default return a new CustomImages map with
// empty images for all languages.
func Default() CustomImages {
	defaultImages := images.MapValues()

	customImages := make(CustomImages, len(defaultImages))

	for lang := range defaultImages {
		customImages[lang] = ""
	}

	return customImages
}

// MustParseCustomImages parse a input to CustomImages.
//
// If some error occur the default values will be returned and the error
// will be logged.
func MustParseCustomImages(input map[string]interface{}) CustomImages {
	customImages, err := parseCustomImages(input)
	if err != nil {
		logger.LogErrorWithLevel(messages.MsgErrorWhileParsingCustomImages, err)
		return Default()
	}
	return customImages
}

// nolint: funlen
func parseCustomImages(input map[string]interface{}) (CustomImages, error) {
	customImg := make(CustomImages, len(input))

	for language, value := range input {
		// TODO(matheus): We should rename CSharp const value.
		if language == "csharp" {
			language = string(languages.CSharp)
		}

		lang := languages.ParseStringToLanguage(language)
		if lang == languages.Unknown {
			return nil, fmt.Errorf("invalid language %s", language)
		}
		v, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("invalid value %v. Must be a string", value)
		}
		customImg[lang] = v
	}

	return customImg, nil
}
