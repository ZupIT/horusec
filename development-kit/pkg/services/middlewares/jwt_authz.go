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
	"context"
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	repositoryRepo "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/repository"
	accountEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/account"
	"github.com/google/uuid"
	"net/http"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	"github.com/go-chi/chi"
)

const RepositoryPermissionsCtxKey CtxKey = "repositoryPermissions"

type IJWTAuthMiddleware interface {
	IsRepositoryMember(next http.Handler) http.Handler
	IsRepositoryAdmin(next http.Handler) http.Handler
	BindRepositoryPermissions(next http.Handler) http.Handler
}

type JWTAuthMiddleware struct {
	repositoryRepo repositoryRepo.IRepository
}

func NewJWTAuthMiddleware(databaseRead SQL.InterfaceRead, databaseWrite SQL.InterfaceWrite) IJWTAuthMiddleware {
	return &JWTAuthMiddleware{
		repositoryRepo: repositoryRepo.NewRepository(databaseRead, databaseWrite),
	}
}

func (j *JWTAuthMiddleware) IsRepositoryMember(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		permissions, err := j.getPermissionsOrFail(w, r)
		if err != nil {
			return
		}

		repositoryID := chi.URLParam(r, "repositoryID")

		if _, isMember := permissions[repositoryID]; !isMember {
			companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
			accountCompany, errCompany := j.repositoryRepo.GetAccountCompanyRole(j.getAccountIDByToken(r), companyID)

			if errCompany != nil || accountCompany.Role != accountEnums.Admin {
				httpUtil.StatusForbidden(w, errors.ErrorUnauthorized)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (j *JWTAuthMiddleware) IsRepositoryAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		permissions, err := j.getPermissionsOrFail(w, r)
		if err != nil {
			return
		}

		repositoryID := chi.URLParam(r, "repositoryID")
		if role, isMember := permissions[repositoryID]; !isMember || role != "admin" {
			companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
			accountCompany, errCompany := j.repositoryRepo.GetAccountCompanyRole(j.getAccountIDByToken(r), companyID)

			if errCompany != nil || accountCompany.Role != accountEnums.Admin {
				httpUtil.StatusForbidden(w, errors.ErrorUnauthorized)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (j *JWTAuthMiddleware) BindRepositoryPermissions(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		permissions, err := j.getPermissionsOrFail(w, r)
		if err != nil {
			return
		}
		newContext := context.WithValue(r.Context(), RepositoryPermissionsCtxKey, permissions)
		next.ServeHTTP(w, r.WithContext(newContext))
	})
}

func (j *JWTAuthMiddleware) getPermissionsOrFail(w http.ResponseWriter, r *http.Request) (map[string]string, error) {
	permissions, err := jwt.GetRepositoryPermissionsByJWTTOken(r.Header.Get("Authorization"))
	if err != nil {
		httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
		return nil, err
	}

	return permissions, nil
}

func (j *JWTAuthMiddleware) getAccountIDByToken(r *http.Request) uuid.UUID {
	accountID, _ := jwt.GetAccountIDByJWTToken(r.Header.Get("Authorization"))
	return accountID
}
