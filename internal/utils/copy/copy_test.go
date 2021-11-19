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

package copy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ZupIT/horusec/internal/utils/copy"
	"github.com/ZupIT/horusec/internal/utils/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCopy(t *testing.T) {
	src := testutil.GoExample1
	dst := filepath.Join(t.TempDir(), t.Name())

	tmpFile, err := os.CreateTemp(t.TempDir(), "test-symlink")
	require.Nil(t, err, "Expected nil error to create temp file")

	symlinkFile := filepath.Join(src, "symlink")
	err = os.Symlink(tmpFile.Name(), symlinkFile)
	require.NoError(t, err, "Expected nil error to create symlink file: %v", err)

	t.Cleanup(func() {
		err := tmpFile.Close()
		assert.NoError(t, err, "Expected nil error to close temp file: %v", err)

		err = os.Remove(symlinkFile)
		assert.NoError(t, err, "Expected nil error to clean up symlink file: %v", err)
	})

	err = copy.Copy(src, dst, func(src string) bool {
		ext := filepath.Ext(src)
		return ext == ".mod" || ext == ".sum"
	})

	assert.NoError(t, err)

	assert.DirExists(t, dst)
	assert.DirExists(t, filepath.Join(dst, "api", "routes"))
	assert.DirExists(t, filepath.Join(dst, "api", "util"))

	assert.NoFileExists(t, filepath.Join(dst, "symlink"))
	assert.FileExists(t, filepath.Join(dst, "api", "server.go"))
	assert.FileExists(t, filepath.Join(dst, "api", "routes", "healthcheck.go"))
	assert.FileExists(t, filepath.Join(dst, "api", "util", "util.go"))

	assert.NoFileExists(t, filepath.Join(dst, "go.mod"))
	assert.NoFileExists(t, filepath.Join(dst, "go.sum"))

}
