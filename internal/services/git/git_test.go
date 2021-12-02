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

package git

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestGetCommitAuthor(t *testing.T) {
	cfg := &config.Config{
		StartOptions: config.StartOptions{
			ProjectPath:        testutil.RootPath,
			EnableCommitAuthor: true,
		},
	}
	service := Git{
		config: cfg,
	}

	t.Run("Should success get commit author", func(t *testing.T) {
		author := service.CommitAuthor("1-2", "README.md")
		assert.NotEmpty(t, author.Email)
		assert.NotEqual(t, "-", author.Email)
		assert.NotEmpty(t, author.Message)
		assert.NotEqual(t, "-", author.Message)
		assert.NotEmpty(t, author.Author)
		assert.NotEqual(t, "-", author.Author)
		assert.NotEmpty(t, author.CommitHash)
		assert.NotEqual(t, "-", author.CommitHash)
		assert.NotEmpty(t, author.Date)
		assert.NotEqual(t, "-", author.Date)
	})

	t.Run("Should return commit author not found when something went wrong while executing cmd", func(t *testing.T) {
		author := service.CommitAuthor("999999", "")
		assert.Equal(t, author, service.newCommitAuthorNotFound())
	})

	t.Run("Should return commit author not found when line or path not found", func(t *testing.T) {
		author := service.CommitAuthor("1", "-")
		assert.Equal(t, author, service.newCommitAuthorNotFound())
	})

	t.Run("Should return commit author not found when parameters is empty", func(t *testing.T) {
		author := service.CommitAuthor("", "./")
		assert.Equal(t, author, service.newCommitAuthorNotFound())
	})

	t.Run("Should return commit author not found when not exists path", func(t *testing.T) {
		author := service.CommitAuthor("1", "./some_path")
		assert.Equal(t, author, service.newCommitAuthorNotFound())
	})

	t.Run("Should return commit author not found invalid output", func(t *testing.T) {
		author := service.parseOutput([]byte(`{"invalid": "json-schema"`))
		assert.Equal(t, author, service.newCommitAuthorNotFound())
	})

	t.Run("Should return commit author not found when disable commit author", func(t *testing.T) {
		cfg := &config.Config{
			StartOptions: config.StartOptions{
				ProjectPath: testutil.RootPath,
			},
		}
		author := New(cfg).CommitAuthor("1-2", "README.md")
		assert.Equal(t, author, service.newCommitAuthorNotFound())
	})

	t.Run("Should return commit author not found when file has not yet been commited", func(t *testing.T) {
		tmp, err := os.Create("temp-file")
		require.Nil(t, err, "Expected nil error to create temp file: %v", err)

		t.Cleanup(func() {
			assert.NoError(t, tmp.Close(), "Expected nil error to close temp file")
			err := os.Remove(tmp.Name())
			require.Nil(t, err, "Expected nil error to delete temp file: %v", err)
		})

		author := service.CommitAuthor("1-2", tmp.Name())
		assert.Equal(t, author, service.newCommitAuthorNotFound())
	})

	t.Run("Should return commit author from first line when line is zero", func(t *testing.T) {
		author := service.CommitAuthor("0", "README.md")
		assert.NotEqual(t, author, service.newCommitAuthorNotFound())
	})

	t.Run("Should return a new service", func(t *testing.T) {
		assert.NotEmpty(t, New(&config.Config{}))
	})

	t.Run("Should not return git diff in output", func(t *testing.T) {
		bytes, err := service.executeCMD("1", "README.md")

		assert.NoError(t, err)
		assert.NotEmpty(t, bytes)
		assert.NotContains(t, string(bytes), "diff --git")
	})
}

func TestRepositoryIsShallow(t *testing.T) {
	shallowRepository := filepath.Join(os.TempDir(), "horusec-shallow")
	_, err := exec.Command(
		"git",
		"clone",
		"--depth=1",
		fmt.Sprintf("file://%s", testutil.RootPath),
		shallowRepository,
	).Output()
	require.Nil(t, err, "Expected nil error to shallow clone repository: %v", err)

	t.Cleanup(func() {
		assert.NoError(
			t,
			os.RemoveAll(shallowRepository),
			"Expected nil error to remove shallow repository",
		)
	})

	testcases := []struct {
		name     string
		cfg      *config.Config
		expected bool
	}{
		{
			name: "NotShallow",
			cfg: &config.Config{
				StartOptions: config.StartOptions{
					ProjectPath: testutil.RootPath,
				},
			},
			expected: false,
		},
		{
			name: "IsShallow",
			cfg: &config.Config{
				StartOptions: config.StartOptions{
					ProjectPath: shallowRepository,
				},
			},
			expected: true,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, RepositoryIsShallow(tt.cfg))
		})
	}
}
