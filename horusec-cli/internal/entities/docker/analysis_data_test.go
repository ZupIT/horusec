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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsInvalid(t *testing.T) {
	t.Run("should return false when valid", func(t *testing.T) {
		data := &AnalysisData{
			DefaultImage: "docker.io/test:latest",
			CMD:          "test",
		}

		assert.False(t, data.IsInvalid())
	})

	t.Run("should return true when invalid data", func(t *testing.T) {
		data := &AnalysisData{}
		assert.True(t, data.IsInvalid())
	})
}

func TestSetData(t *testing.T) {
	t.Run("should success set data", func(t *testing.T) {
		data := &AnalysisData{
			CMD: "test",
		}

		assert.NotEmpty(t, data.SetData("other-host.io/t/test:latest", "t", "v1.0.0"))
	})

}

func TestGetImageWithRegistry(t *testing.T) {
	t.Run("should success get image with registry for custom image", func(t *testing.T) {
		data := &AnalysisData{
			CustomImage: "test/custom",
		}

		assert.Equal(t, "test/custom", data.GetImageWithRegistry())
	})

	t.Run("should success get image with registry for custom image", func(t *testing.T) {
		data := &AnalysisData{
			DefaultImage: "test/default",
		}

		assert.Equal(t, "test/default", data.GetImageWithRegistry())
	})
}

func TestGetImageWithoutRegistry(t *testing.T) {
	t.Run("should success get image without registry for custom image", func(t *testing.T) {
		data := &AnalysisData{
			CustomImage: "test/custom",
		}

		assert.Equal(t, "custom", data.GetImageWithoutRegistry())
	})

	t.Run("should success get image without registry for custom image", func(t *testing.T) {
		data := &AnalysisData{
			DefaultImage: "test/default",
		}

		assert.Equal(t, "default", data.GetImageWithoutRegistry())
	})

	t.Run("should return full image path when failed to get index", func(t *testing.T) {
		data := &AnalysisData{
			DefaultImage: "test",
		}

		assert.Equal(t, "test", data.GetImageWithoutRegistry())
	})
}
