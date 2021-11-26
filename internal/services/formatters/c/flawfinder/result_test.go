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

package flawfinder

import (
	"testing"

	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/stretchr/testify/assert"
)

func TestGetDetails(t *testing.T) {
	result := &flawFinderResult{
		Warning:    "test",
		Suggestion: "test",
		Note:       "test",
	}

	t.Run("should success get details", func(t *testing.T) {
		details := result.getDetails()

		assert.NotEmpty(t, details)
		assert.Equal(t, "test test test", details)
	})
}

func TestGetSeverity(t *testing.T) {
	result := &flawFinderResult{
		Level: "0",
	}

	t.Run("should get severities low", func(t *testing.T) {
		assert.Equal(t, severities.Low, result.getSeverity())

		result.Level = "0"
		assert.Equal(t, severities.Low, result.getSeverity())

		result.Level = "1"
		assert.Equal(t, severities.Low, result.getSeverity())
	})

	t.Run("should get severities medium", func(t *testing.T) {
		result.Level = "2"
		assert.Equal(t, severities.Medium, result.getSeverity())

		result.Level = "3"
		assert.Equal(t, severities.Medium, result.getSeverity())
	})

	t.Run("should get severities high", func(t *testing.T) {
		result.Level = "4"
		assert.Equal(t, severities.High, result.getSeverity())
	})

	t.Run("should get severities critical", func(t *testing.T) {
		result.Level = "5"
		assert.Equal(t, severities.Critical, result.getSeverity())
	})
}

func TestGetFilename(t *testing.T) {
	result := &flawFinderResult{
		File: "./test.c",
	}

	t.Run("should success get filename", func(t *testing.T) {
		filename := result.getFilename()

		assert.NotEmpty(t, filename)
		assert.NotContains(t, filename, "./")
		assert.Equal(t, "test.c", filename)
	})
}
