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

package scs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseOutput(t *testing.T) {
	t.Run("should success get first run of the array", func(t *testing.T) {
		analysis := scsAnalysis{Runs: []*scsRun{{}}}

		assert.NotNil(t, analysis.getRun())
	})

	t.Run("should return nil when empty slice", func(t *testing.T) {
		analysis := scsAnalysis{}

		assert.Nil(t, analysis.getRun())
	})
}

func TestMapVulnerabilitiesByID(t *testing.T) {
	t.Run("should success map vulnerabilities by id", func(t *testing.T) {
		analysis := scsAnalysis{
			Runs: []*scsRun{
				{
					Tool: scsTool{
						Driver: scsDriver{
							Rules: []*scsRule{
								{
									ID: "test",
									FullDescription: scsMessage{
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

		result := analysis.vulnerabilitiesByID()
		assert.NotEmpty(t, result)
	})
}

func TestGetLine(t *testing.T) {
	t.Run("should success get line", func(t *testing.T) {
		result := scsResult{
			RuleID: "test",
			Message: scsMessage{
				Text: "test",
			},
			Locations: []*scsLocation{
				{
					PhysicalLocation: scsPhysicalLocation{
						ArtifactLocation: scsArtifactLocation{
							URI: "test",
						},
						Region: scsRegion{
							StartLine:   1,
							StartColumn: 2,
						},
					},
				},
			},
		}

		assert.Equal(t, "1", result.getLine())
	})

	t.Run("should return empty string", func(t *testing.T) {
		result := scsResult{
			Locations: []*scsLocation{},
		}

		assert.Empty(t, result.getLine())
	})
}

func TestGetColumn(t *testing.T) {
	t.Run("should success get column", func(t *testing.T) {
		result := scsResult{
			RuleID: "test",
			Message: scsMessage{
				Text: "test",
			},
			Locations: []*scsLocation{
				{
					PhysicalLocation: scsPhysicalLocation{
						ArtifactLocation: scsArtifactLocation{
							URI: "test",
						},
						Region: scsRegion{
							StartLine:   1,
							StartColumn: 2,
						},
					},
				},
			},
		}

		assert.Equal(t, "2", result.getColumn())
	})

	t.Run("should return empty string", func(t *testing.T) {
		result := scsResult{
			Locations: []*scsLocation{},
		}

		assert.Empty(t, result.getColumn())
	})
}

func TestGetVulnName(t *testing.T) {
	t.Run("should success get vulnerability name", func(t *testing.T) {
		result := scsResult{
			RuleID: "test",
			Message: scsMessage{
				Text: "test",
			},
			Locations: []*scsLocation{
				{
					PhysicalLocation: scsPhysicalLocation{
						ArtifactLocation: scsArtifactLocation{
							URI: "test",
						},
						Region: scsRegion{
							StartLine:   1,
							StartColumn: 2,
						},
					},
				},
			},
		}

		assert.Equal(t, "test", result.getVulnName())
	})
}

func TestGetFile(t *testing.T) {
	t.Run("should success get file", func(t *testing.T) {
		result := scsResult{
			RuleID: "test",
			Message: scsMessage{
				Text: "test",
			},
			Locations: []*scsLocation{
				{
					PhysicalLocation: scsPhysicalLocation{
						ArtifactLocation: scsArtifactLocation{
							URI: "file:///src/test",
						},
						Region: scsRegion{
							StartLine:   1,
							StartColumn: 2,
						},
					},
				},
			},
		}

		assert.Equal(t, "test", result.getFile())
	})

	t.Run("should return empty string", func(t *testing.T) {
		result := scsResult{
			Locations: []*scsLocation{},
		}

		assert.Empty(t, result.getFile())
	})
}

func TestGetDescription(t *testing.T) {
	t.Run("should return empty string", func(t *testing.T) {
		rule := scsRule{
			ID: "test",
			FullDescription: scsMessage{
				Text: "{test}",
			},
			HelpURI: "test",
		}

		assert.Equal(t, "test\ntest For more information, check the following url (test).", rule.getDescription("test"))
	})
}
