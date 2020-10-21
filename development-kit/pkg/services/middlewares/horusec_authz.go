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
	"bytes"
	"encoding/json"
	"fmt"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	httpEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/http"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	httpClient "github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/client"
	httpResponse "github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/response"
	"net/http"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
)

type IHorusAuthzMiddleware interface {
	IsCompanyMember(next http.Handler) http.Handler
	IsCompanyAdmin(next http.Handler) http.Handler
	IsRepositoryMember(next http.Handler) http.Handler
	IsRepositoryAdmin(next http.Handler) http.Handler
	IsRepositorySupervisor(next http.Handler) http.Handler
}

type HorusAuthzMiddleware struct {
	httpUtil httpClient.Interface
}

func NewHorusAuthzMiddleware() IHorusAuthzMiddleware {
	return &HorusAuthzMiddleware{
		httpUtil: httpClient.NewHTTPClient(10),
	}
}

func (h *HorusAuthzMiddleware) IsCompanyMember(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isValid, err := h.validateRequest(r, authEnums.CompanyMember)
		if err != nil || !isValid {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *HorusAuthzMiddleware) IsCompanyAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isValid, err := h.validateRequest(r, authEnums.CompanyAdmin)
		if err != nil || !isValid {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *HorusAuthzMiddleware) IsRepositoryMember(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isValid, err := h.validateRequest(r, authEnums.RepositoryMember)
		if err != nil || !isValid {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *HorusAuthzMiddleware) IsRepositorySupervisor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isValid, err := h.validateRequest(r, authEnums.RepositorySupervisor)
		if err != nil || !isValid {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *HorusAuthzMiddleware) IsRepositoryAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isValid, err := h.validateRequest(r, authEnums.RepositoryAdmin)
		if err != nil || !isValid {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *HorusAuthzMiddleware) validateRequest(r *http.Request, role authEnums.HorusecRoles) (bool, error) {
	companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
	repositoryID, _ := uuid.Parse(chi.URLParam(r, "repositoryID"))

	return h.sendRequestAuthentication(r.Header.Get("Authorization"), role, companyID, repositoryID)
}

func (h *HorusAuthzMiddleware) sendRequestAuthentication(token string, role authEnums.HorusecRoles, companyID,
	repositoryID uuid.UUID) (bool, error) {
	req, _ := http.NewRequest(http.MethodPost, h.getHorusecAuthURL(),
		bytes.NewReader(h.newAuthorizationData(token, role, companyID, repositoryID)))

	return h.parseResponse(h.httpUtil.DoRequest(req, nil))
}

func (h *HorusAuthzMiddleware) getHorusecAuthURL() string {
	return fmt.Sprintf("%s/api/auth/authorize",
		env.GetEnvOrDefault("HORUSEC_AUTH_URL", "http://0.0.0.0:8006"))
}

func (h *HorusAuthzMiddleware) newAuthorizationData(token string, role authEnums.HorusecRoles, companyID,
	repositoryID uuid.UUID) []byte {
	authorizationData := &authEntities.AuthorizationData{
		Token:        token,
		Role:         role,
		CompanyID:    companyID,
		RepositoryID: repositoryID,
	}

	return authorizationData.ToBytes()
}

func (h *HorusAuthzMiddleware) parseResponse(response httpResponse.Interface, err error) (bool, error) {
	if err != nil {
		return false, err
	}

	responseContent := httpEntities.Response{}
	body, _ := response.GetBody()
	err = json.Unmarshal(body, &responseContent)
	return responseContent.Content.(bool), err
}
