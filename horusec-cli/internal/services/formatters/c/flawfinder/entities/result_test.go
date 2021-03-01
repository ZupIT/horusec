package entities

import (
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/stretchr/testify/assert"
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

	t.Run("should get severity low", func(t *testing.T) {
		assert.Equal(t, severity.Low, result.GetSeverity())

		result.Level = "0"
		assert.Equal(t, severity.Low, result.GetSeverity())

		result.Level = "1"
		assert.Equal(t, severity.Low, result.GetSeverity())
	})

	t.Run("should get severity medium", func(t *testing.T) {
		result.Level = "2"
		assert.Equal(t, severity.Medium, result.GetSeverity())

		result.Level = "3"
		assert.Equal(t, severity.Medium, result.GetSeverity())
	})

	t.Run("should get severity high", func(t *testing.T) {
		result.Level = "4"
		assert.Equal(t, severity.High, result.GetSeverity())
	})

	t.Run("should get severity critical", func(t *testing.T) {
		result.Level = "5"
		assert.Equal(t, severity.Critical, result.GetSeverity())
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
