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
	t.Run("should success map vulnerabilities by id", func(t *testing.T) {
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
