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

package company

import (
	"encoding/json"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"

	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	rolesEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewAccountCompanyFromReadCLoser(t *testing.T) {
	t.Run("should success parse to account company", func(t *testing.T) {
		bytes, _ := json.Marshal(&roles.AccountCompany{
			AccountID: uuid.New(),
			CompanyID: uuid.New(),
			Role:      rolesEnum.Admin,
		})

		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))
		useCases := NewCompanyUseCases()

		accountCompany, err := useCases.NewAccountCompanyFromReadCLoser(readCloser)

		assert.NoError(t, err)
		assert.NotNil(t, accountCompany)
	})

	t.Run("should return error when invalid body", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader(""))
		useCases := NewCompanyUseCases()

		accountCompany, err := useCases.NewAccountCompanyFromReadCLoser(readCloser)

		assert.Error(t, err)
		assert.Nil(t, accountCompany)
	})
}

func TestNewCompanyFromReadCloser(t *testing.T) {
	t.Run("should success parse to company", func(t *testing.T) {
		bytes, _ := json.Marshal(&accountEntities.Company{
			CompanyID: uuid.New(),
			Name:      "test",
		})

		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))
		useCases := NewCompanyUseCases()

		company, err := useCases.NewCompanyFromReadCloser(readCloser)

		assert.NoError(t, err)
		assert.NotNil(t, company)
	})

	t.Run("should return error when invalid body", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader(""))
		useCases := NewCompanyUseCases()

		company, err := useCases.NewCompanyFromReadCloser(readCloser)

		assert.Error(t, err)
		assert.Nil(t, company)
	})
}

func TestNewCompanyApplicationAdminFromReadCloser(t *testing.T) {
	t.Run("should success parse to company", func(t *testing.T) {
		bytes, _ := json.Marshal(&accountEntities.CompanyApplicationAdmin{
			CompanyID:  uuid.New(),
			Name:       "test",
			AdminEmail: "admin@example.com",
		})

		readCloser := ioutil.NopCloser(strings.NewReader(string(bytes)))
		useCases := NewCompanyUseCases()

		company, err := useCases.NewCompanyApplicationAdminFromReadCloser(readCloser)

		assert.NoError(t, err)
		assert.NotNil(t, company)
	})

	t.Run("should return error when invalid body", func(t *testing.T) {
		readCloser := ioutil.NopCloser(strings.NewReader(""))
		useCases := NewCompanyUseCases()

		company, err := useCases.NewCompanyApplicationAdminFromReadCloser(readCloser)

		assert.Error(t, err)
		assert.Nil(t, company)
	})
}

func TestIsInvalidLdapGroup(t *testing.T) {
	t.Run("should return true when invalid group", func(t *testing.T) {
		useCases := NewCompanyUseCases()

		result := useCases.IsInvalidLdapGroup([]string{"group1", "group2"}, []string{"test1", "test2"})

		assert.True(t, result)
	})

	t.Run("should return false when valid group", func(t *testing.T) {
		useCases := NewCompanyUseCases()

		result := useCases.IsInvalidLdapGroup([]string{"group1", "group2"}, []string{"test1", "group1"})

		assert.False(t, result)
	})

	t.Run("should return true when empty groups", func(t *testing.T) {
		useCases := NewCompanyUseCases()

		result := useCases.IsInvalidLdapGroup([]string{"", ""}, []string{"", ""})

		assert.True(t, result)
	})
}
