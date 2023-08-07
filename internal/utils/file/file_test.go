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

package file_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	dotnetcli "github.com/ZupIT/horusec/internal/services/formatters/csharp/dotnet_cli"
	"github.com/ZupIT/horusec/internal/utils/file"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestGetFilePathIntoBasePath(t *testing.T) {
	t.Run("Should return path correctly", func(t *testing.T) {
		filePath := filepath.Join("file", "file_test.go")
		volume := filepath.Join(testutil.RootPath, "internal")
		response, err := file.GetPathFromFilename(filePath, volume)
		assert.NoError(t, err)
		assert.NotEqual(t, response, filePath)
		assert.Equal(t, filepath.Join("utils", "file", "file_test.go"), response)
	})
	t.Run("Should return filePath because not found", func(t *testing.T) {
		filePath := "some_other_not_existing_file.go"
		volume := testutil.RootPath
		response, err := file.GetPathFromFilename(filePath, volume)
		assert.NoError(t, err)
		assert.Equal(t, "", response)
	})
	t.Run("Should return filePath because base path is wrong", func(t *testing.T) {
		filePath := "some_other_not_existing_file.go"
		volume := "S0M3 N0T E3X1$t"
		response, err := file.GetPathFromFilename(filePath, volume)
		assert.Error(t, err)
		assert.Equal(t, "", response)
	})
}

func TestGetSubPathByExtension(t *testing.T) {
	t.Run("Should return sub path for .go", func(t *testing.T) {
		response := file.GetSubPathByExtension(testutil.GoExample1, "", "*.go")
		assert.Equal(t, filepath.Join("api", "routes"), response)
	})

	t.Run("Should return empty path for not found extension", func(t *testing.T) {
		response := file.GetSubPathByExtension(testutil.GoExample1, "", "*.test")
		assert.Equal(t, "", response)
	})
}

func TestCreateAndWriteFile(t *testing.T) {
	wd := t.TempDir()
	t.Run("Should create a file with input and return no error", func(t *testing.T) {
		expectedInput := "some input"
		filename := filepath.Join(wd, "someFile")
		err := file.CreateAndWriteFile(expectedInput, filename)
		assert.NoError(t, err)

		_, err = os.Stat(filename)
		exists := !errors.Is(err, os.ErrNotExist)
		assert.True(t, exists)
		if exists {
			input, err := os.ReadFile(filename)
			assert.NoError(t, err)
			assert.Equal(t, expectedInput, string(input))
		}
	})
	t.Run("Should create a file in current directory "+
		"with absolute filepath with input and return no error when invalid filepath", func(t *testing.T) {
		filename := "invalidPathForFile"
		expectedInput := "some input"

		err := file.CreateAndWriteFile(expectedInput, filename)
		assert.NoError(t, err)

		_, err = os.Stat(filename)
		assert.NoError(t, err)

		exists := !errors.Is(err, os.ErrNotExist)
		assert.True(t, exists)

		if exists {
			path, err := filepath.Abs(filename)
			assert.NoError(t, err)
			input, err := os.ReadFile(path)
			assert.NoError(t, err)
			assert.Equal(t, expectedInput, string(input))
			t.Cleanup(func() {
				_ = os.Remove(path)
			})
		}
	})
}

func TestGetDependencyCodeFilepathAndLine(t *testing.T) {
	t.Run("Should run with success", func(t *testing.T) {
		dependencyInfo, err := file.GetDependencyCodeFilepathAndLine(
			testutil.CsharpExample1, "", []string{"Microsoft.AspNetCore.Http", "2.2.2"}, dotnetcli.CsProjExt,
		)
		expectedCode := "    <PackageReference Include=\"Microsoft.AspNetCore.Http\" Version=\"2.2.2\"/>"
		expectedFile := filepath.Join(testutil.CsharpExample1, "NetCoreVulnerabilities", "NetCoreVulnerabilities.csproj")
		expectedLine := "7"
		assert.NoError(t, err)
		assert.Equal(t, expectedLine, dependencyInfo.Line)
		assert.Equal(t, expectedFile, dependencyInfo.Path)
		assert.Equal(t, expectedCode, dependencyInfo.Code)
	})
	t.Run("Should return empty when path is invalid", func(t *testing.T) {
		dependencyInfo, err := file.GetDependencyCodeFilepathAndLine(
			"invalidPath", "", []string{"Microsoft.AspNetCore.Http"}, dotnetcli.CsProjExt,
		)
		assert.Error(t, err)
		assert.ErrorIs(t, err, os.ErrNotExist)
		assert.Nil(t, dependencyInfo)
	})
	t.Run("Should return empty when path is valid but has no files", func(t *testing.T) {
		dependencyInfo, err := file.GetDependencyCodeFilepathAndLine(
			t.TempDir(), "", []string{"Microsoft.AspNetCore.Http"}, dotnetcli.CsProjExt,
		)
		assert.NoError(t, err)
		assert.NotNil(t, dependencyInfo)
		assert.Empty(t, dependencyInfo.Line)
		assert.Empty(t, dependencyInfo.Code)
		assert.Empty(t, dependencyInfo.Path)
	})
	t.Run("Should found the file but not found the code expected in this file", func(t *testing.T) {
		dependencyInfo, err := file.GetDependencyCodeFilepathAndLine(
			testutil.CsharpExample1, "", []string{"This_Code_Not_Exists_In_File", "5.2.3"}, dotnetcli.CsProjExt,
		)
		assert.NoError(t, err)
		assert.Empty(t, dependencyInfo.Line)
		assert.Empty(t, dependencyInfo.Path)
		assert.Empty(t, dependencyInfo.Code)
	})
}

func TestGetCode(t *testing.T) {
	dir := t.TempDir()
	expectedInput := "some input"
	filename := "someFile"
	path := filepath.Join(dir, filename)
	err := file.CreateAndWriteFile(expectedInput, path)
	assert.NoError(t, err)
	t.Run("Should get a code from a file with input and return no error", func(t *testing.T) {
		result, err := file.GetCode(dir, filename, "1")
		assert.NoError(t, err)
		assert.Equal(t, expectedInput, result)
	})
	t.Run("Should not get a code from a file with input and return error", func(t *testing.T) {
		err = file.CreateAndWriteFile("notExpectedInput", path)
		assert.NoError(t, err)

		result, err := file.GetCode(dir, filename, "1")
		assert.NoError(t, err)
		assert.NotEqual(t, expectedInput, result)
	})
	t.Run("Should not get a code from a file with input and return empty when line is empty", func(t *testing.T) {
		result, err := file.GetCode(dir, filename, "3")
		assert.NoError(t, err)
		assert.Equal(t, "", result)
	})
	t.Run("Should not get a code from a file with input and return empty when line is invalid", func(t *testing.T) {
		result, err := file.GetCode(dir, filename, "-3")
		assert.NoError(t, err)
		assert.Equal(t, "", result)
	})
	t.Run("Should not get a code from a file with input and return error when dir path is invalid", func(t *testing.T) {
		result, err := file.GetCode("invalidDirPath", filename, "3")
		assert.Error(t, err)
		assert.Equal(t, "", result)
	})
	t.Run("Should not get a code from a file with input and return error when filename is invalid", func(t *testing.T) {
		result, err := file.GetCode(dir, "invalidFilename", "3")
		assert.Error(t, err)
		assert.Equal(t, "", result)
	})
}

func TestGetFilenameByExt(t *testing.T) {
	dir := t.TempDir()
	expectedInput := "some input"
	filename := "someFile.go"
	path := filepath.Join(dir, filename)
	err := file.CreateAndWriteFile(expectedInput, path)
	assert.NoError(t, err)
	t.Run("Should get a filename by extension with no error", func(t *testing.T) {
		resultFilename, err := file.GetFilenameByExt(dir, "", ".go")
		assert.NoError(t, err)
		assert.Equal(t, filename, resultFilename)
	})
	t.Run("Should get a empty filename by extension when ext is not found", func(t *testing.T) {
		resultFilename, err := file.GetFilenameByExt(dir, "", ".potato")
		assert.NoError(t, err)
		assert.Equal(t, "", resultFilename)
	})
	t.Run("Should get a empty filename by extension and error when path is valid", func(t *testing.T) {
		resultFilename, err := file.GetFilenameByExt("invalidPath", "", ".go")
		assert.Error(t, err)
		assert.Equal(t, "", resultFilename)
	})
}
