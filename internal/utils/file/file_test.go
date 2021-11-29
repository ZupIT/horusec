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
		volume := testutil.RootPath
		response := file.GetPathFromFilename(filePath, volume)
		assert.NotEqual(t, response, filePath)
		assert.Equal(t, filepath.Join("internal", "utils", "file", "file_test.go"), response)
	})
	t.Run("Should return filePath because not found", func(t *testing.T) {
		filePath := "some_other_not_existing_file.go"
		volume := testutil.RootPath
		response := file.GetPathFromFilename(filePath, volume)
		assert.Equal(t, "", response)
	})
	t.Run("Should return filePath because base path is wrong", func(t *testing.T) {
		filePath := "some_other_not_existing_file.go"
		volume := "S0M3 N0T E3X1$t"
		response := file.GetPathFromFilename(filePath, volume)
		assert.Equal(t, "", response)
	})
}

func TestGetSubPathByExtension(t *testing.T) {
	t.Run("Should return sub path for .go", func(t *testing.T) {
		path, _ := filepath.Abs(".")
		response := file.GetSubPathByExtension(path, "", "*.go")
		assert.Equal(t, "", response)
	})

	t.Run("Should not matches matches", func(t *testing.T) {
		path, _ := filepath.Abs(".")
		response := file.GetSubPathByExtension(path, "test", "*.test")
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
		code, file, line := file.GetDependencyCodeFilepathAndLine(testutil.CsharpExample1, "", dotnetcli.CsProjExt, "Microsoft.AspNetCore.Http")
		expectedCode := "<PackageReference Include=\"Microsoft.AspNetCore.Http\" Version=\"2.2.2\"/>"
		expectedFile := filepath.Join(testutil.CsharpExample1, "NetCoreVulnerabilities", "NetCoreVulnerabilities.csproj")
		expectedLine := "7"
		assert.Equal(t, expectedLine, line)
		assert.Equal(t, expectedFile, file)
		assert.Equal(t, expectedCode, code)
	})
	t.Run("Should return empty when path is invalid", func(t *testing.T) {
		code, file, line := file.GetDependencyCodeFilepathAndLine("invalidPath", "", dotnetcli.CsProjExt, "Microsoft.AspNetCore.Http")
		assert.Zero(t, code)
		assert.Zero(t, file)
		assert.Zero(t, line)
	})
	t.Run("Should return empty when path is valid but has no files", func(t *testing.T) {
		code, file, line := file.GetDependencyCodeFilepathAndLine(t.TempDir(), "", dotnetcli.CsProjExt, "Microsoft.AspNetCore.Http")
		assert.Zero(t, code)
		assert.Zero(t, file)
		assert.Zero(t, line)
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
