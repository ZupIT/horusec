package entities

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
)

func TestGetDetails(t *testing.T) {
	result := &Result{
		Warning:    "test",
		Suggestion: "test",
		Note:       "test",
	}

	t.Run("should success get details", func(t *testing.T) {
		details := result.GetDetails()

		assert.NotEmpty(t, details)
		assert.Equal(t, "test test test", details)
	})

}

func TestGetSeverity(t *testing.T) {
	result := &Result{
		Level: "0",
	}

	t.Run("should get severities low", func(t *testing.T) {
		assert.Equal(t, severities.Low, result.GetSeverity())

		result.Level = "0"
		assert.Equal(t, severities.Low, result.GetSeverity())

		result.Level = "1"
		assert.Equal(t, severities.Low, result.GetSeverity())
	})

	t.Run("should get severities medium", func(t *testing.T) {
		result.Level = "2"
		assert.Equal(t, severities.Medium, result.GetSeverity())

		result.Level = "3"
		assert.Equal(t, severities.Medium, result.GetSeverity())
	})

	t.Run("should get severities high", func(t *testing.T) {
		result.Level = "4"
		assert.Equal(t, severities.High, result.GetSeverity())
	})

	t.Run("should get severities critical", func(t *testing.T) {
		result.Level = "5"
		assert.Equal(t, severities.Critical, result.GetSeverity())
	})
}

func TestGetFilename(t *testing.T) {
	result := &Result{
		File: "./test.c",
	}

	t.Run("should success get filename", func(t *testing.T) {
		filename := result.GetFilename()

		assert.NotEmpty(t, filename)
		assert.NotContains(t, filename, "./")
		assert.Equal(t, "test.c", filename)
	})

}
