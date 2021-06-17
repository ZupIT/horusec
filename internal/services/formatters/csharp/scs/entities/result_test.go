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
