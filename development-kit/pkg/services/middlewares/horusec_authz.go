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
	"context"
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	authGrpc "github.com/ZupIT/horusec/development-kit/pkg/services/grpc/auth"
	httpClient "github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/client"
	"google.golang.org/grpc"
	"net/http"

	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	"github.com/go-chi/chi"
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
	httpUtil   httpClient.Interface
	grpcClient authGrpc.AuthServiceClient
	ctx        context.Context
}

func NewHorusAuthzMiddleware(grpcCon grpc.ClientConnInterface) IHorusAuthzMiddleware {
	return &HorusAuthzMiddleware{
		httpUtil:   httpClient.NewHTTPClient(10),
		grpcClient: authGrpc.NewAuthServiceClient(grpcCon),
		ctx:        context.Background(),
	}
}

func (h *HorusAuthzMiddleware) SetContextAccountID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.setContextAndReturn(next, w, r)
	})
}

func (h *HorusAuthzMiddleware) IsApplicationAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r, configAuth, err := h.getConfigAuthAndSetInContext(r)
		if err != nil {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}
		if configAuth.ApplicationAdminEnable {
			response, err := h.grpcClient.IsAuthorized(h.ctx, h.setAuthorizedData(r, authEnums.ApplicationAdmin))
			if err != nil || !response.GetIsAuthorized() {
				httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
				return
			}
		}
		h.setContextAndReturn(next, w, r)
	})
}

func (h *HorusAuthzMiddleware) getConfigAuthAndSetInContext(r *http.Request) (
	*http.Request, authEntities.ConfigAuth, error) {
	configAuth, err := h.getConfigAuth()
	if err != nil {
		return r, authEntities.ConfigAuth{}, errors.ErrorUnauthorized
	}
	return h.setConfigAuthInContextAndReturnRequest(r, configAuth), configAuth, nil
}

func (h *HorusAuthzMiddleware) IsCompanyMember(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response, err := h.grpcClient.IsAuthorized(h.ctx, h.setAuthorizedData(r, authEnums.CompanyMember))
		if err != nil || !response.GetIsAuthorized() {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}

		h.setContextAndReturn(next, w, r)
	})
}

func (h *HorusAuthzMiddleware) IsCompanyAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response, err := h.grpcClient.IsAuthorized(h.ctx, h.setAuthorizedData(r, authEnums.CompanyAdmin))
		if err != nil || !response.GetIsAuthorized() {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}

		h.setContextAndReturn(next, w, r)
	})
}

func (h *HorusAuthzMiddleware) IsRepositoryMember(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response, err := h.grpcClient.IsAuthorized(h.ctx, h.setAuthorizedData(r, authEnums.RepositoryMember))
		if err != nil || !response.GetIsAuthorized() {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}

		h.setContextAndReturn(next, w, r)
	})
}

func (h *HorusAuthzMiddleware) IsRepositorySupervisor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response, err := h.grpcClient.IsAuthorized(h.ctx, h.setAuthorizedData(r, authEnums.RepositorySupervisor))
		if err != nil || !response.GetIsAuthorized() {
			httpUtil.StatusUnauthorized(w, errors.ErrorUnauthorized)
			return
		}

		h.setContextAndReturn(next, w, r)
	})
}

func (h *HorusAuthzMiddleware) IsRepositoryAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response, err := h.grpcClient.IsAuthorized(h.ctx, h.setAuthorizedData(r, authEnums.RepositoryAdmin))
		if err != nil || !response.GetIsAuthorized() {
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

func (h *HorusAuthzMiddleware) setAuthorizedData(r *http.Request,
	role authEnums.HorusecRoles) *authGrpc.IsAuthorizedData {
	return &authGrpc.IsAuthorizedData{
		Token:        r.Header.Get("Authorization"),
		Role:         role.ToString(),
		CompanyID:    chi.URLParam(r, "companyID"),
		RepositoryID: chi.URLParam(r, "repositoryID"),
	}
}

func (h *HorusAuthzMiddleware) setGetAccountIDData(token string) *authGrpc.GetAccountIDData {
	return &authGrpc.GetAccountIDData{
		Token: token,
	}
}

func (h *HorusAuthzMiddleware) setAccountIDInContext(r *http.Request, token string) (context.Context, error) {
	response, err := h.grpcClient.GetAccountID(h.ctx, h.setGetAccountIDData(token))
	if err != nil {
		return nil, err
	}

	return context.WithValue(r.Context(), authEnums.AccountID, response.AccountID), nil
}

func (h *HorusAuthzMiddleware) getConfigAuth() (authEntities.ConfigAuth, error) {
	response, err := h.grpcClient.GetAuthConfig(h.ctx, &authGrpc.GetAuthConfigData{})
	if err != nil {
		return authEntities.ConfigAuth{}, err
	}

	return authEntities.ConfigAuth{
		ApplicationAdminEnable: response.GetApplicationAdminEnable(),
		AuthType:               authEnums.AuthorizationType(response.GetAuthType()),
	}, nil
}

func (h *HorusAuthzMiddleware) setConfigAuthInContextAndReturnRequest(
	r *http.Request, configAuth authEntities.ConfigAuth) *http.Request {
	ctx := context.WithValue(r.Context(), authEnums.ConfigAuth, configAuth)
	return r.WithContext(ctx)
}
