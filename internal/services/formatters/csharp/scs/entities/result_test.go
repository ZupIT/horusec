package entities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetLine(t *testing.T) {
	t.Run("should success get line", func(t *testing.T) {
		result := Result{
			RuleID: "test",
			Message: Message{
				Text: "test",
			},
			Locations: []*Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{
							URI: "test",
						},
						Region: Region{
							StartLine:   1,
							StartColumn: 2,
						},
					},
				},
			},
		}

		assert.Equal(t, "1", result.GetLine())
	})

	t.Run("should return empty string", func(t *testing.T) {
		result := Result{
			Locations: []*Location{},
		}

		assert.Empty(t, result.GetLine())
	})
}

func TestGetColumn(t *testing.T) {
	t.Run("should success get column", func(t *testing.T) {
		result := Result{
			RuleID: "test",
			Message: Message{
				Text: "test",
			},
			Locations: []*Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{
							URI: "test",
						},
						Region: Region{
							StartLine:   1,
							StartColumn: 2,
						},
					},
				},
			},
		}

		assert.Equal(t, "2", result.GetColumn())
	})

	t.Run("should return empty string", func(t *testing.T) {
		result := Result{
			Locations: []*Location{},
		}

		assert.Empty(t, result.GetColumn())
	})
}

func TestGetVulnName(t *testing.T) {
	t.Run("should success get vulnerability name", func(t *testing.T) {
		result := Result{
			RuleID: "test",
			Message: Message{
				Text: "test",
			},
			Locations: []*Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{
							URI: "test",
						},
						Region: Region{
							StartLine:   1,
							StartColumn: 2,
						},
					},
				},
			},
		}

		assert.Equal(t, "test", result.GetVulnName())
	})
}

func TestGetFile(t *testing.T) {
	t.Run("should success get file", func(t *testing.T) {
		result := Result{
			RuleID: "test",
			Message: Message{
				Text: "test",
			},
			Locations: []*Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{
							URI: "file:///src/test",
						},
						Region: Region{
							StartLine:   1,
							StartColumn: 2,
						},
					},
				},
			},
		}

		assert.Equal(t, "test", result.GetFile())
	})

	t.Run("should return empty string", func(t *testing.T) {
		result := Result{
			Locations: []*Location{},
		}

		assert.Empty(t, result.GetFile())
	})
}
