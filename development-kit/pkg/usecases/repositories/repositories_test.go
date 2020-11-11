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

package repositories

import (
	"encoding/json"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/dto"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"
	"io/ioutil"
	"strings"
	"testing"

	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	rolesEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewRepositoryFromReadCloser(t *testing.T) {
	t.Run("should success parse read closer to repository", func(t *testing.T) {
		bytes, _ := json.Marshal(&accountEntities.Repository{
			Name:         "test",
			Description:  "test",
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
		})
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewRepositoryUseCases()
		account, err := useCases.NewRepositoryFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.NotEmpty(t, account)
	})

	t.Run("should return error when invalid read closer", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader(""))

		useCases := NewRepositoryUseCases()
		_, err := useCases.NewRepositoryFromReadCloser(readCloser)
		assert.Error(t, err)
	})
}

func TestNewAccountRepositoryFromReadCloser(t *testing.T) {
	t.Run("should success parse read closer to account repository", func(t *testing.T) {
		bytes, _ := json.Marshal(&roles.AccountRepository{
			AccountID:    uuid.New(),
			RepositoryID: uuid.New(),
			Role:         rolesEnum.Admin,
		})
		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewRepositoryUseCases()
		account, err := useCases.NewAccountRepositoryFromReadCloser(readCloser)
		assert.NoError(t, err)
		assert.NotEmpty(t, account)
	})

	t.Run("should return error when invalid read closer", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader(""))

		useCases := NewRepositoryUseCases()
		_, err := useCases.NewAccountRepositoryFromReadCloser(readCloser)
		assert.Error(t, err)
	})
}

func TestNewInviteUserFromReadCloser(t *testing.T) {
	t.Run("should success parse read closer to invite user", func(t *testing.T) {
		bytes, _ := json.Marshal(&dto.InviteUser{
			CompanyID:    uuid.New(),
			RepositoryID: uuid.New(),
			Role:         rolesEnum.Admin,
			Email:        "test@test.com",
		})

		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))

		useCases := NewRepositoryUseCases()

		account, err := useCases.NewInviteUserFromReadCloser(readCloser)

		assert.NoError(t, err)
		assert.NotEmpty(t, account)
	})

	t.Run("should return error when invalid read closer", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader(""))

		useCases := NewRepositoryUseCases()

		_, err := useCases.NewInviteUserFromReadCloser(readCloser)

		assert.Error(t, err)
	})
}
