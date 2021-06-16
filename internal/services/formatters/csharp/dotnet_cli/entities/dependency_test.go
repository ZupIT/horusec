package entities

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
)

func TestSetName(t *testing.T) {
	t.Run("should success set name", func(t *testing.T) {
		dependency := &Dependency{}

		dependency.SetName("test")
		assert.Equal(t, "test", dependency.Name)
	})
}

func TestSetVersion(t *testing.T) {
	t.Run("should success set version", func(t *testing.T) {
		dependency := &Dependency{}

		dependency.SetVersion("test")
		assert.Equal(t, "test", dependency.Version)
	})
}

func TestSetDescription(t *testing.T) {
	t.Run("should success set description", func(t *testing.T) {
		dependency := &Dependency{}

		dependency.SetDescription("test")
		assert.Equal(t, "test", dependency.Description)
	})
}

func TestSetSeverity(t *testing.T) {
	t.Run("should success set severity", func(t *testing.T) {
		dependency := &Dependency{}

		dependency.SetSeverity("test")
		assert.Equal(t, "test", dependency.Severity)

		dependency.SetSeverity("\u001B[31m   Critical")
		assert.Equal(t, "Critical", dependency.Severity)

		dependency.SetSeverity("\u001B[33m   Moderate")
		assert.Equal(t, "Moderate", dependency.Severity)
	})
}

func TestGetSeverity(t *testing.T) {
	t.Run("should success get severity", func(t *testing.T) {
		dependency := &Dependency{}

		dependency.Severity = "Critical"
		assert.Equal(t, severities.Critical, dependency.GetSeverity())

		dependency.Severity = "High"
		assert.Equal(t, severities.High, dependency.GetSeverity())

		dependency.Severity = "Moderate"
		assert.Equal(t, severities.Medium, dependency.GetSeverity())

		dependency.Severity = "Low"
		assert.Equal(t, severities.Low, dependency.GetSeverity())

		dependency.Severity = "Test"
		assert.Equal(t, severities.Unknown, dependency.GetSeverity())
	})
}
