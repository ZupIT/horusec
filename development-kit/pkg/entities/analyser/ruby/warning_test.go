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

package ruby

import (
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/severity"
	"github.com/stretchr/testify/assert"
)

func TestGetDetails(t *testing.T) {
	t.Run("Should return output details and message", func(t *testing.T) {
		output := Warning{
			Details: "test",
			Message: "test",
		}

		assert.Equal(t, "test test", output.GetDetails())
	})
}

func TestGetSeverity(t *testing.T) {
	t.Run("Should return output high severity", func(t *testing.T) {
		output := Warning{Confidence: "High"}
		assert.Equal(t, severity.High, output.GetSeverity())
	})

	t.Run("Should return output medium severity", func(t *testing.T) {
		output := Warning{Confidence: "Medium"}
		assert.Equal(t, severity.Medium, output.GetSeverity())
	})

	t.Run("Should return output low severity", func(t *testing.T) {
		output := Warning{Confidence: "Low"}
		assert.Equal(t, severity.Low, output.GetSeverity())
	})

	t.Run("Should return output no sec severity", func(t *testing.T) {
		output := Warning{}
		assert.Equal(t, severity.NoSec, output.GetSeverity())
	})
}

func TestGetLine(t *testing.T) {
	t.Run("Should parse line to string and return", func(t *testing.T) {
		output := Warning{
			Line: 123,
		}

		assert.Equal(t, "123", output.GetLine())
	})
}
