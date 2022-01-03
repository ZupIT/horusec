// Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

package yarnaudit

import (
	"testing"

	"github.com/ZupIT/horusec-devkit/pkg/enums/severities"
	"github.com/stretchr/testify/assert"
)

func TestGetVersion(t *testing.T) {
	t.Run("should return finding version", func(t *testing.T) {
		issue := issue{
			Findings: []finding{
				{
					Version: "test",
				},
			},
		}

		assert.Equal(t, "test", issue.getVersion())
	})

	t.Run("should return no version", func(t *testing.T) {
		issue := issue{}
		assert.Empty(t, issue.getVersion())
	})
}

func TestGetSeverity(t *testing.T) {
	t.Run("should return a low severity", func(t *testing.T) {
		issue := issue{
			Severity: "low",
		}

		assert.Equal(t, severities.Low, issue.getSeverity())
	})

	t.Run("should return a medium severity", func(t *testing.T) {
		issue := issue{
			Severity: "moderate",
		}

		assert.Equal(t, severities.Medium, issue.getSeverity())
	})

	t.Run("should return a critical severity", func(t *testing.T) {
		issue := issue{
			Severity: "critical",
		}

		assert.Equal(t, severities.Critical, issue.getSeverity())
	})

	t.Run("should return a info severity", func(t *testing.T) {
		issue := issue{
			Severity: "info",
		}

		assert.Equal(t, severities.Info, issue.getSeverity())
	})

	t.Run("should return a unknown severity", func(t *testing.T) {
		issue := issue{
			Severity: "",
		}

		assert.Equal(t, severities.Unknown, issue.getSeverity())
	})
}
