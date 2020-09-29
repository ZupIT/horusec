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

package zip

import (
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestMock(t *testing.T) {
	t.Run("Should mock UnZip correctly", func(t *testing.T) {
		m := &Mock{}
		m.On("UnZip").Return(nil)
		assert.NoError(t, m.UnZip("", ""))
	})
	t.Run("Should mock CompressFolderToZip correctly", func(t *testing.T) {
		m := &Mock{}
		m.On("CompressFolderToZip").Return(nil)
		assert.NoError(t, m.CompressFolderToZip("", ""))
	})
	t.Run("Should mock ConvertFilesToZip correctly", func(t *testing.T) {
		m := &Mock{}
		m.On("ConvertFilesToZip").Return(nil)
		assert.NoError(t, m.ConvertFilesToZip([]string{}, "", ""))
	})
}

func TestNewZip(t *testing.T) {
	t.Run("Should return type correctly", func(t *testing.T) {
		assert.IsType(t, NewZip(), &Zip{})
	})
}

func TestZip_CompressFolderToZip(t *testing.T) {
	t.Run("Should compress one file to zip", func(t *testing.T) {
		err := NewZip().CompressFolderToZip("../zip", "./tmp.zip")
		assert.NoError(t, err)
		if err == nil {
			assert.NoError(t, os.RemoveAll("./tmp.zip"))
		}
	})
}

func TestZip_ConvertFilesToZip(t *testing.T) {
	t.Run("Should compress one file to zip", func(t *testing.T) {
		files := []string{
			"./zip.go",
		}
		err := NewZip().ConvertFilesToZip(files, "./", "tmp")
		assert.NoError(t, err)
		if err == nil {
			assert.NoError(t, os.RemoveAll("./.horusec"))
		}
	})
	t.Run("Should compress multiple file to zip", func(t *testing.T) {
		files := []string{
			"./zip.go",
			"./zip_test.go",
			"./zip_mock.go",
		}
		err := NewZip().ConvertFilesToZip(files, "./", "tmp")
		assert.NoError(t, err)
		if err == nil {
			assert.NoError(t, os.RemoveAll("./.horusec"))
		}
	})
}

func TestZip_UnZip(t *testing.T) {
	t.Run("Should unzip file with success", func(t *testing.T) {
		z := NewZip()
		files := []string{
			"./zip.go",
			"./zip_test.go",
			"./zip_mock.go",
		}
		err := z.ConvertFilesToZip(files, "./", "tmp")
		assert.NoError(t, err)
		if err == nil {
			err = z.UnZip("./.horusec/tmp.zip", "./.horusec/"+uuid.New().String())
			assert.NoError(t, err)
			if err == nil {
				assert.NoError(t, os.RemoveAll("./.horusec"))
			}
		}
	})
}
