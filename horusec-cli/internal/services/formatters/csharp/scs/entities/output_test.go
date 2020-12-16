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

package entities

import (
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/stretchr/testify/assert"
)

func TestIsTypeSC(t *testing.T) {
	t.Run("should return true for security issue", func(t *testing.T) {
		output := ScsResult{
			Filename:      "test",
			IssueSeverity: "test",
			ErrorID:       "SC",
			IssueText:     "test",
		}

		assert.True(t, output.IsSecurityIssue())
	})

	t.Run("should return false for security issue", func(t *testing.T) {
		output := ScsResult{
			Filename:      "test",
			IssueSeverity: "test",
			ErrorID:       "CS",
			IssueText:     "test",
		}

		assert.False(t, output.IsSecurityIssue())
	})

	t.Run("should return false when empty error ID", func(t *testing.T) {
		output := ScsResult{
			Filename:      "test",
			IssueSeverity: "test",
			ErrorID:       "",
			IssueText:     "test",
		}

		assert.False(t, output.IsSecurityIssue())
	})
}

func TestIsEmpty(t *testing.T) {
	t.Run("should false for empty output", func(t *testing.T) {
		output := ScsResult{
			Filename:      "test",
			IssueSeverity: "test",
			ErrorID:       "test",
			IssueText:     "test",
		}

		assert.False(t, output.IsEmpty())
	})

	t.Run("should true for empty output", func(t *testing.T) {
		output := ScsResult{}

		assert.True(t, output.IsEmpty())

		output.Filename = "test"

		assert.True(t, output.IsEmpty())

		output.IssueSeverity = "test"

		assert.True(t, output.IsEmpty())

		output.ErrorID = "test"

		assert.True(t, output.IsEmpty())

		output.Filename = "test"

		assert.True(t, output.IsEmpty())

		output.IssueText = "test"

		assert.False(t, output.IsEmpty())
	})
}

func TestIsValid(t *testing.T) {
	t.Run("should return true for valid output", func(t *testing.T) {
		output := ScsResult{
			Filename:      "test",
			IssueSeverity: "test",
			ErrorID:       "SC",
			IssueText:     "test",
		}

		assert.True(t, output.IsValid())
	})

	t.Run("should return false for invalid output", func(t *testing.T) {
		output := ScsResult{
			Filename:      "test",
			IssueSeverity: "test",
			ErrorID:       "CS",
			IssueText:     "test",
		}

		assert.False(t, output.IsValid())
	})
}

func TestGetDotNetSeverityByCode(t *testing.T) {
	output := ScsResult{}

	t.Run("should return a low severity", func(t *testing.T) {
		output.ErrorID = "SCS0021"
		assert.Equal(t, severity.Low, output.GetSeverity())
	})

	t.Run("should return a medium severity", func(t *testing.T) {
		output.ErrorID = "SCS0012"
		assert.Equal(t, severity.Medium, output.GetSeverity())
	})

	t.Run("should return a high severity", func(t *testing.T) {
		output.ErrorID = "SCS0014"
		assert.Equal(t, severity.High, output.GetSeverity())
	})

	t.Run("should return a no sec severity", func(t *testing.T) {
		output.ErrorID = ""
		assert.Equal(t, severity.NoSec, output.GetSeverity())
	})
}

func TestGetLine(t *testing.T) {
	t.Run("should return filename line", func(t *testing.T) {
		output := ScsResult{Filename: "Vulnerabilities.cs(23,26)"}
		assert.NotEmpty(t, output.GetLine())
		assert.Equal(t, "23", output.GetLine())

		output.Filename = "Vulnerabilities.cs(454,766)"
		assert.NotEmpty(t, output.GetLine())
		assert.Equal(t, "454", output.GetLine())

		output.Filename = "Vulnerabilities.cs(3213,4565)"
		assert.NotEmpty(t, output.GetLine())
		assert.Equal(t, "3213", output.GetLine())
	})

	t.Run("should return empty string when invalid data", func(t *testing.T) {
		output := ScsResult{Filename: ""}
		assert.Empty(t, output.GetLine())
	})
}

func TestGetColumn(t *testing.T) {
	t.Run("should return filename column", func(t *testing.T) {
		output := ScsResult{Filename: "Vulnerabilities.cs(23,26)"}
		assert.NotEmpty(t, output.GetColumn())
		assert.Equal(t, "26", output.GetColumn())

		output.Filename = "Vulnerabilities.cs(454,766)"
		assert.NotEmpty(t, output.GetColumn())
		assert.Equal(t, "766", output.GetColumn())

		output.Filename = "Vulnerabilities.cs(3213,4565)"
		assert.NotEmpty(t, output.GetColumn())
		assert.Equal(t, "4565", output.GetColumn())
	})

	t.Run("should return empty string when invalid data", func(t *testing.T) {
		output := ScsResult{Filename: ""}
		assert.Empty(t, output.GetColumn())
	})
}

func TestGetFilename(t *testing.T) {
	t.Run("should return filename", func(t *testing.T) {
		output := ScsResult{Filename: "Vulnerabilities.cs(23,26)"}
		assert.NotEmpty(t, output.GetFilename())
		assert.Equal(t, "Vulnerabilities.cs", output.GetFilename())

		output.Filename = "Test.cs(12312,3123123)"
		assert.NotEmpty(t, output.GetFilename())
		assert.Equal(t, "Test.cs", output.GetFilename())
	})

	t.Run("should return empty string when invalid data", func(t *testing.T) {
		output := ScsResult{Filename: ""}
		assert.Empty(t, output.GetFilename())
	})
}
