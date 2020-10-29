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

package account

import (
	"testing"

	rolesEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/account"

	"github.com/stretchr/testify/assert"
)

func TestCompanyValidate(t *testing.T) {
	t.Run("validate should return an error when the struct is not valid", func(t *testing.T) {
		company := &Company{}
		assert.Error(t, company.Validate())
	})

	t.Run("valide should return nil when the struct is valid", func(t *testing.T) {
		company := &Company{Name: "test"}
		assert.Nil(t, company.Validate())
	})
}

func TestCompanyGetTable(t *testing.T) {
	t.Run("should return the table name", func(t *testing.T) {
		company := &Company{}
		assert.Equal(t, "companies", company.GetTable())
	})
}

func TestSetCreateDataCompany(t *testing.T) {
	t.Run("should success set create data", func(t *testing.T) {
		company := &Company{}
		assert.NotEmpty(t, company.SetCreateData())
	})
}

func TestSetUpdateDataCompany(t *testing.T) {
	t.Run("should success set update data", func(t *testing.T) {
		company := &Company{}
		assert.NotEmpty(t, company.SetUpdateData())
	})
}

func TestToCompanyResponse(t *testing.T) {
	t.Run("should success parse to company response", func(t *testing.T) {
		company := &Company{
			Name:        "test",
			Description: "test",
		}

		assert.NotEmpty(t, company.ToCompanyResponse(rolesEnum.Admin))
	})
}

func TestGetAuthzMemberCompany(t *testing.T) {
	t.Run("should success get authz member", func(t *testing.T) {
		company := &Company{
			AuthzMember: "test",
		}

		assert.NotEmpty(t, company.GetAuthzMember())
	})
}

func TestGetAuthzSupervisorCompany(t *testing.T) {
	t.Run("should success get authz supervisor", func(t *testing.T) {
		company := &Company{}

		assert.Empty(t, company.GetAuthzSupervisor())
	})
}

func TestGetAuthzAdminCompany(t *testing.T) {
	t.Run("should success get authz admin", func(t *testing.T) {
		company := &Company{
			AuthzAdmin: "test",
		}

		assert.NotEmpty(t, company.GetAuthzAdmin())
	})
}

func TestToBytesCompany(t *testing.T) {
	t.Run("should success parse to bytes", func(t *testing.T) {
		company := &Company{Name: "test"}

		assert.NotEmpty(t, company.ToBytes())
	})
}
