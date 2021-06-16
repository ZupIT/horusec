package entities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseOutput(t *testing.T) {
	t.Run("should success get first run of the array", func(t *testing.T) {
		analysis := Analysis{Runs: []*Run{{}}}

		assert.NotNil(t, analysis.GetRun())
	})

	t.Run("should return nil when empty slice", func(t *testing.T) {
		analysis := Analysis{}

		assert.Nil(t, analysis.GetRun())
	})
}

func TestMapVulnerabilitiesByID(t *testing.T) {
	t.Run("should success map vuln by id", func(t *testing.T) {
		analysis := Analysis{
			Runs: []*Run{
				{
					Tool: Tool{
						Driver: Driver{
							Rules: []*Rule{
								{
									ID: "test",
									FullDescription: Message{
										Text: "test",
									},
									HelpURI: "test",
								},
							},
						},
					},
				},
			},
		}

		result := analysis.MapVulnerabilitiesByID()
		assert.NotEmpty(t, result)
	})
}
