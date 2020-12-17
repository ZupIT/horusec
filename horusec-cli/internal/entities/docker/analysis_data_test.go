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

package docker

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIsValid(t *testing.T) {
	t.Run("Should return false for valid data ", func(t *testing.T) {
		data := &AnalysisData{
			ImagePath: "docker.io/test:latest",
			CMD:       "test",
		}

		assert.False(t, data.IsInvalid())
	})

	t.Run("Should return true for invalid data ", func(t *testing.T) {
		data := &AnalysisData{}
		assert.True(t, data.IsInvalid())
	})
}

func TestGetContainerImageNameWithTag(t *testing.T) {
	t.Run("Should success set image path in config path", func(t *testing.T) {
		data := &AnalysisData{
			CMD: "test",
		}
		data.SetFullImagePath("other-host.io/t/test:latest", "t", "v1.0.0")
		assert.Equal(t, "other-host.io/t/test:latest", data.ImagePath)
	})
	t.Run("Should success set image path default", func(t *testing.T) {
		data := &AnalysisData{
			CMD: "test",
		}
		data.SetFullImagePath("", "t", "v1.0.0")
		assert.NotEmpty(t, "docker.io/t:v1.0.0", data.ImagePath)
	})
}
