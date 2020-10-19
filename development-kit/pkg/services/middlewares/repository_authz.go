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

//nolint
package middlewares

import (
	"net/http"

	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	repoAccountRepository "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/account_repository"
	repositoryRepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/repository"
	accountEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	accountUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/account"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
)

type IRepositoryAuthzMiddleware interface {
	IsRepositoryMember(next http.Handler) http.Handler
	IsRepositoryAdmin(next http.Handler) http.Handler
	IsRepositorySupervisor(next http.Handler) http.Handler
}

type repositoryAuthzMiddleware struct {
	repoAccountRepository repoAccountRepository.IAccountRepository
	repositoryRepo        repositoryRepo.IRepository
	accountUseCases       accountUseCases.IAccount
}

func NewRepositoryAuthzMiddleware(
	databaseRead SQL.InterfaceRead, databaseWrite SQL.InterfaceWrite) IRepositoryAuthzMiddleware {
	return &repositoryAuthzMiddleware{
		repoAccountRepository: repoAccountRepository.NewAccountRepositoryRepository(databaseRead, databaseWrite),
		accountUseCases:       accountUseCases.NewAccountUseCases(),
		repositoryRepo:        repositoryRepo.NewRepository(databaseRead, databaseWrite),
	}
}

func (rm *repositoryAuthzMiddleware) IsRepositoryMember(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accountID, err := jwt.GetAccountIDByJWTToken(r.Header.Get("Authorization"))
		if err != nil {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}

		repositoryID, _ := uuid.Parse(chi.URLParam(r, "repositoryID"))
		_, err = rm.repoAccountRepository.GetAccountRepository(accountID, repositoryID)
		if err != nil {
			companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
			accountCompany, errCompany := rm.repositoryRepo.GetAccountCompanyRole(accountID, companyID)

			if errCompany != nil || accountCompany.Role != accountEnums.Admin {
				httpUtil.StatusForbidden(w, errors.ErrorUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (rm *repositoryAuthzMiddleware) IsRepositoryAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accountID, err := jwt.GetAccountIDByJWTToken(r.Header.Get("Authorization"))
		if err != nil {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}

		repositoryID, _ := uuid.Parse(chi.URLParam(r, "repositoryID"))
		accountRepository, errRepository := rm.repoAccountRepository.GetAccountRepository(accountID, repositoryID)
		if errRepository != nil || accountRepository.Role != accountEnums.Admin {
			companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
			accountCompany, errCompany := rm.repositoryRepo.GetAccountCompanyRole(accountID, companyID)

			if errCompany != nil || accountCompany.Role != accountEnums.Admin {
				httpUtil.StatusForbidden(w, errors.ErrorUnauthorized)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

//nolint
func (rm *repositoryAuthzMiddleware) IsRepositorySupervisor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accountID, err := jwt.GetAccountIDByJWTToken(r.Header.Get("Authorization"))
		if err != nil {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}

		repositoryID, _ := uuid.Parse(chi.URLParam(r, "repositoryID"))
		accountRepository, err := rm.repoAccountRepository.GetAccountRepository(accountID, repositoryID)
		if err != nil || accountRepository.Role != accountEnums.Supervisor && accountRepository.Role != accountEnums.Admin {
			companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
			accountCompany, errCompany := rm.repositoryRepo.GetAccountCompanyRole(accountID, companyID)

			if errCompany != nil || accountCompany.Role != accountEnums.Admin {
				httpUtil.StatusForbidden(w, errors.ErrorUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
