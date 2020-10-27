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
	"context"
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
	SetContextAccountID(next http.Handler) http.Handler
	IsApplicationAdmin(next http.Handler) http.Handler
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

func (h *HorusAuthzMiddleware) SetContextAccountID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.setContextAndReturn(next, w, r)
	})
}

func (h *HorusAuthzMiddleware) IsApplicationAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		configAuth, err := h.getConfigAuthAndSetInContext(r)
		if err != nil {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}
		if configAuth.ApplicationAdminEnable {
			isValid, err := h.validateRequest(r, authEnums.ApplicationAdmin)
			if err != nil || !isValid {
				httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
				return
			}
		}
		h.setContextAndReturn(next, w, r)
	})
}

func (h *HorusAuthzMiddleware) getConfigAuthAndSetInContext(r *http.Request) (authEntities.ConfigAuth, error) {
	configAuth, err := h.getConfigAuth()
	if err != nil {
		return authEntities.ConfigAuth{}, errors.ErrorUnauthorized
	}
	h.setConfigAuthInContext(r, configAuth)
	return configAuth, nil
}

func (h *HorusAuthzMiddleware) IsCompanyMember(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isValid, err := h.validateRequest(r, authEnums.CompanyMember)
		if err != nil || !isValid {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}

		h.setContextAndReturn(next, w, r)
	})
}

func (h *HorusAuthzMiddleware) IsCompanyAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isValid, err := h.validateRequest(r, authEnums.CompanyAdmin)
		if err != nil || !isValid {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}

		h.setContextAndReturn(next, w, r)
	})
}

func (h *HorusAuthzMiddleware) IsRepositoryMember(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isValid, err := h.validateRequest(r, authEnums.RepositoryMember)
		if err != nil || !isValid {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}

		h.setContextAndReturn(next, w, r)
	})
}

func (h *HorusAuthzMiddleware) IsRepositorySupervisor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isValid, err := h.validateRequest(r, authEnums.RepositorySupervisor)
		if err != nil || !isValid {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}

		h.setContextAndReturn(next, w, r)
	})
}

func (h *HorusAuthzMiddleware) IsRepositoryAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isValid, err := h.validateRequest(r, authEnums.RepositoryAdmin)
		if err != nil || !isValid {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}

		h.setContextAndReturn(next, w, r)
	})
}

func (h *HorusAuthzMiddleware) setContextAndReturn(next http.Handler, w http.ResponseWriter, r *http.Request) {
	ctx, err := h.setAccountIDInContext(r, r.Header.Get("Authorization"))
	if err != nil {
		httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
		return
	}

	next.ServeHTTP(w, r.WithContext(ctx))
}

func (h *HorusAuthzMiddleware) validateRequest(r *http.Request, role authEnums.HorusecRoles) (bool, error) {
	companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
	repositoryID, _ := uuid.Parse(chi.URLParam(r, "repositoryID"))

	return h.sendRequestAuthentication(r.Header.Get("Authorization"), role, companyID, repositoryID)
}

func (h *HorusAuthzMiddleware) sendRequestAuthentication(token string, role authEnums.HorusecRoles, companyID,
	repositoryID uuid.UUID) (bool, error) {
	req, _ := http.NewRequest(http.MethodPost, h.getHorusecAuthURL("/authorize"),
		bytes.NewReader(h.newAuthorizationData(token, role, companyID, repositoryID)))

	return h.parseResponseBool(h.httpUtil.DoRequest(req, nil))
}

func (h *HorusAuthzMiddleware) getHorusecAuthURL(subPath string) string {
	return fmt.Sprintf("%s/api/auth%s",
		env.GetEnvOrDefault("HORUSEC_AUTH_URL", "http://0.0.0.0:8006"), subPath)
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

func (h *HorusAuthzMiddleware) parseResponseBool(
	response httpResponse.Interface, err error) (isValid bool, errParse error) {
	if err != nil {
		return false, err
	}

	responseContent := httpEntities.Response{}
	body, _ := response.GetBody()
	if errParse := json.Unmarshal(body, &responseContent); errParse != nil {
		return false, errParse
	}

	return isValid, json.Unmarshal(responseContent.ContentToBytes(), &isValid)
}

func (h *HorusAuthzMiddleware) parseResponseAccountID(
	response httpResponse.Interface, err error) (accountID uuid.UUID, errParse error) {
	if err != nil {
		return uuid.Nil, err
	}

	responseContent := httpEntities.Response{}
	body, _ := response.GetBody()
	if errParse := json.Unmarshal(body, &responseContent); errParse != nil {
		return uuid.Nil, errParse
	}

	return accountID, json.Unmarshal(responseContent.ContentToBytes(), &accountID)
}

func (h *HorusAuthzMiddleware) sendRequestGetAccountID(token string) (uuid.UUID, error) {
	req, _ := http.NewRequest(http.MethodGet, h.getHorusecAuthURL("/account-id"), nil)
	req.Header.Add("Authorization", token)

	return h.parseResponseAccountID(h.httpUtil.DoRequest(req, nil))
}

func (h *HorusAuthzMiddleware) setAccountIDInContext(r *http.Request, token string) (context.Context, error) {
	accountID, err := h.sendRequestGetAccountID(token)
	if err != nil {
		return nil, err
	}

	return context.WithValue(r.Context(), authEnums.AccountID, accountID.String()), nil
}

func (h *HorusAuthzMiddleware) getConfigAuth() (authEntities.ConfigAuth, error) {
	req, _ := http.NewRequest(http.MethodGet, h.getHorusecAuthURL("/config"), nil)

	res, err := h.httpUtil.DoRequest(req, nil)
	if err != nil {
		return authEntities.ConfigAuth{}, err
	}
	return h.parseResponseConfigAuth(res)
}

func (h *HorusAuthzMiddleware) setConfigAuthInContext(
	r *http.Request, configAuth authEntities.ConfigAuth) context.Context {
	return context.WithValue(r.Context(), authEnums.ConfigAuth, configAuth)
}

func (h *HorusAuthzMiddleware) parseResponseConfigAuth(
	response httpResponse.Interface) (entity authEntities.ConfigAuth, err error) {
	responseContent := httpEntities.Response{}
	body, _ := response.GetBody()
	if errParse := json.Unmarshal(body, &responseContent); errParse != nil {
		return authEntities.ConfigAuth{}, errParse
	}
	return responseContent.Content.(authEntities.ConfigAuth), nil
}
