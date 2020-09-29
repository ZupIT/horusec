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

package middlewares

import (
	"net/http"

	repositoryAccountCompany "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_company"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	accountUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/account"

	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	accountEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
)

type ICompanyAuthzMiddleware interface {
	IsCompanyMember(next http.Handler) http.Handler
	IsCompanyAdmin(next http.Handler) http.Handler
}

type CompanyAuthzMiddleware struct {
	repoAccountCompany repositoryAccountCompany.IAccountCompany
	accountUseCases    accountUseCases.IAccount
}

func NewCompanyAuthzMiddleware(
	databaseRead SQL.InterfaceRead, databaseWrite SQL.InterfaceWrite) ICompanyAuthzMiddleware {
	return &CompanyAuthzMiddleware{
		accountUseCases:    accountUseCases.NewAccountUseCases(),
		repoAccountCompany: repositoryAccountCompany.NewAccountCompanyRepository(databaseRead, databaseWrite),
	}
}

//nolint
func (c *CompanyAuthzMiddleware) IsCompanyMember(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accountID, err := jwt.GetAccountIDByJWTToken(r.Header.Get("Authorization"))
		if err != nil {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}

		companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
		_, err = c.repoAccountCompany.GetAccountCompany(accountID, companyID)
		if err != nil {
			httpUtil.StatusForbidden(w, errors.ErrorUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

//nolint
func (c *CompanyAuthzMiddleware) IsCompanyAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accountID, err := jwt.GetAccountIDByJWTToken(r.Header.Get("Authorization"))
		if err != nil {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}

		companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
		accountCompany, err := c.repoAccountCompany.GetAccountCompany(accountID, companyID)
		if err != nil || accountCompany.Role != accountEnums.Admin {
			httpUtil.StatusForbidden(w, errors.ErrorUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
