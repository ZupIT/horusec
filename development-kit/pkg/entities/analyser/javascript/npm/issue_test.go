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

package npm

import (
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/stretchr/testify/assert"
)

func TestGetVersion(t *testing.T) {
	t.Run("should return finding version", func(t *testing.T) {
		issue := Issue{
			Findings: []Finding{
				{
					Version: "test",
				},
			},
		}

		assert.Equal(t, "test", issue.GetVersion())
	})

	t.Run("should return no version", func(t *testing.T) {
		issue := Issue{}
		assert.Empty(t, issue.GetVersion())
	})
}

func TestGetSeverity(t *testing.T) {
	t.Run("should return a low severity", func(t *testing.T) {
		issue := Issue{
			Severity: "low",
		}

		assert.Equal(t, severity.Low, issue.GetSeverity())
	})

	t.Run("should return a medium severity", func(t *testing.T) {
		issue := Issue{
			Severity: "moderate",
		}

		assert.Equal(t, severity.Medium, issue.GetSeverity())
	})

	t.Run("should return a high severity", func(t *testing.T) {
		issue := Issue{
			Severity: "critical",
		}

		assert.Equal(t, severity.High, issue.GetSeverity())
	})

	t.Run("should return a no sec severity", func(t *testing.T) {
		issue := Issue{
			Severity: "sec",
		}

		assert.Equal(t, severity.NoSec, issue.GetSeverity())
	})
}
