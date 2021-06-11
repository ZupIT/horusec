package entities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetVulnerability(t *testing.T) {
	t.Run("should success get vulnerability without cwe", func(t *testing.T) {
		dependence := &Dependence{
			FileName: "test",
			FilePath: "test",
			Vulnerabilities: []*Vulnerability{
				{
					Description: "test",
					Severity:    "test",
					Name:        "test",
				},
			},
		}

		assert.NotNil(t, dependence.GetVulnerability())
	})

	t.Run("should success get vulnerability with cwe", func(t *testing.T) {
		dependence := &Dependence{
			FileName: "test",
			FilePath: "test",
			Vulnerabilities: []*Vulnerability{
				{
					Description: "test",
					Severity:    "test",
					Name:        "CWE test",
				},
			},
		}

		assert.NotNil(t, dependence.GetVulnerability())
	})

	t.Run("should return nil when do not contains vulnerability", func(t *testing.T) {
		dependence := &Dependence{}

		assert.Nil(t, dependence.GetVulnerability())
	})
}

func TestGetFile(t *testing.T) {
	t.Run("should success get file", func(t *testing.T) {
		dependence := &Dependence{
			FilePath: "test?test",
		}

		file := dependence.GetFile()
		assert.NotEmpty(t, file)
		assert.Equal(t, "test", file)
	})

	t.Run("should success get file", func(t *testing.T) {
		dependence := &Dependence{
			FilePath: "test2",
		}

		file := dependence.GetFile()
		assert.NotEmpty(t, file)
		assert.Equal(t, "test2", file)
	})
}
