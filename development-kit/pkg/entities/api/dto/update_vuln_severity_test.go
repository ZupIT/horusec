package dto

import (
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"

	"github.com/stretchr/testify/assert"
)

func TestToBytes(t *testing.T) {
	t.Run("should success parse to bytes", func(t *testing.T) {
		severityDTO := &UpdateVulnSeverity{Severity: severity.Critical}
		assert.NotEmpty(t, severityDTO.ToBytes())
	})
}

func TestValidate(t *testing.T) {
	t.Run("should success return no error when valid severity", func(t *testing.T) {
		severityDTO := &UpdateVulnSeverity{}

		severityDTO.Severity = severity.Critical
		assert.NoError(t, severityDTO.Validate())

		severityDTO.Severity = severity.High
		assert.NoError(t, severityDTO.Validate())

		severityDTO.Severity = severity.Medium
		assert.NoError(t, severityDTO.Validate())

		severityDTO.Severity = severity.Low
		assert.NoError(t, severityDTO.Validate())

		severityDTO.Severity = severity.Info
		assert.NoError(t, severityDTO.Validate())

		severityDTO.Severity = severity.Unknown
		assert.NoError(t, severityDTO.Validate())
	})

	t.Run("should success return no error when invalid severity value", func(t *testing.T) {
		severityDTO := &UpdateVulnSeverity{}

		severityDTO.Severity = "test"
		assert.Error(t, severityDTO.Validate())

		severityDTO.Severity = "error"
		assert.Error(t, severityDTO.Validate())

		severityDTO.Severity = "NOSEC"
		assert.Error(t, severityDTO.Validate())

		severityDTO.Severity = "AUDIT"
		assert.Error(t, severityDTO.Validate())
	})
}
