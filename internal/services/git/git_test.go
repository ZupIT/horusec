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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec/config"
)

func TestGetCommitAuthor(t *testing.T) {
	c := &config.Config{}
	c.ProjectPath = "../../../../"
	c.EnableCommitAuthor = true
	service := Git{
		config: c,
	}

	t.Run("Should success get commit author", func(t *testing.T) {
		author := service.CommitAuthor("1-2", "README.md")
		assert.NotEmpty(t, author.Email)
		assert.NotEmpty(t, author.Message)
		assert.NotEmpty(t, author.Author)
		assert.NotEmpty(t, author.CommitHash)
		assert.NotEmpty(t, author.Date)
	})

	t.Run("Should return error when something went wrong while executing cmd", func(t *testing.T) {
		author := service.CommitAuthor("999999", "")
		assert.Equal(t, author, service.getCommitAuthorNotFound())
	})

	t.Run("Should return error when line or path not found", func(t *testing.T) {
		author := service.CommitAuthor("1", "-")
		assert.Equal(t, author, service.getCommitAuthorNotFound())
	})

	t.Run("Should return error when parameters is empty", func(t *testing.T) {
		author := service.CommitAuthor("", "./")
		assert.Equal(t, author, service.getCommitAuthorNotFound())
	})

	t.Run("Should return error when not exists path", func(t *testing.T) {
		author := service.CommitAuthor("1", "./some_path")
		assert.Equal(t, author, service.getCommitAuthorNotFound())
	})

	t.Run("Should return empty commit author when invalid output", func(t *testing.T) {
		author := service.parseOutputToStruct([]byte("test"))
		assert.Equal(t, author, service.getCommitAuthorNotFound())
	})

	t.Run("Should return a new service", func(t *testing.T) {
		assert.NotEmpty(t, New(&config.Config{}))
	})
}
