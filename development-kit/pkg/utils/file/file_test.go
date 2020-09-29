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

package file

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetPath(t *testing.T) {
	t.Run("Should return path correctly", func(t *testing.T) {
		filePath := "file/file_test.go"
		volume := "../../../.."
		response := GetAbsFilePathIntoBasePath(filePath, volume)
		assert.NotEqual(t, response, filePath)
		assert.Contains(t, response, "/development-kit/pkg/utils/file/file_test.go")
	})
	t.Run("Should return filePath because not found", func(t *testing.T) {
		filePath := "some_other_not_existing_file.go"
		volume := "../../../.."
		response := GetAbsFilePathIntoBasePath(filePath, volume)
		assert.Equal(t, response, filePath)
	})
	t.Run("Should return filePath because base path is wrong", func(t *testing.T) {
		filePath := "some_other_not_existing_file.go"
		volume := "S0M3 N0T E3X1$t"
		response := GetAbsFilePathIntoBasePath(filePath, volume)
		assert.Equal(t, response, filePath)
	})
	t.Run("Should return filePath because base path is not exists", func(t *testing.T) {
		filePath := "some_other_not_existing_file.go"
		volume := "./not_existing_path"
		response := GetAbsFilePathIntoBasePath(filePath, volume)
		assert.Equal(t, response, filePath)
	})
}

func TestGetFilePathIntoBasePath(t *testing.T) {
	t.Run("Should return path correctly", func(t *testing.T) {
		filePath := "file/file_test.go"
		volume := "../../../.."
		response := GetPathIntoFilename(filePath, volume)
		assert.NotEqual(t, response, filePath)
		assert.Contains(t, response, "development-kit/pkg/utils/file/file_test.go")
	})
	t.Run("Should return filePath because not found", func(t *testing.T) {
		filePath := "some_other_not_existing_file.go"
		volume := "../../../.."
		response := GetPathIntoFilename(filePath, volume)
		assert.Equal(t, "", response)
	})
	t.Run("Should return filePath because base path is wrong", func(t *testing.T) {
		filePath := "some_other_not_existing_file.go"
		volume := "S0M3 N0T E3X1$t"
		response := GetPathIntoFilename(filePath, volume)
		assert.Equal(t, "", response)
	})
}
