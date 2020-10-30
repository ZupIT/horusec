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

package auth

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth"   // [swagger-import]
	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/http" // [swagger-import]
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	authUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/auth"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	"github.com/ZupIT/horusec/horusec-auth/config/app"
	authController "github.com/ZupIT/horusec/horusec-auth/internal/controller/auth"
	netHTTP "net/http"
)

type Handler struct {
	authUseCases   authUseCases.IUseCases
	authController authController.IController
	appConfig      *app.Config
}

func NewAuthHandler(
	postgresRead relational.InterfaceRead, postgresWrite relational.InterfaceWrite, appConfig *app.Config) *Handler {
	return &Handler{
		appConfig:      appConfig,
		authUseCases:   authUseCases.NewAuthUseCases(),
		authController: authController.NewAuthController(postgresRead, postgresWrite, appConfig),
	}
}

func (h *Handler) Options(w netHTTP.ResponseWriter, _ *netHTTP.Request) {
	httpUtil.StatusNoContent(w)
}

// @Tags Auth
// @Description get actual type!
// @ID get type
// @Accept  json
// @Produce  json
// @Success 200 {object} http.Response{content=auth.ConfigAuth{}} "STATUS OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Router /api/auth/config [get]
func (h *Handler) Config(w netHTTP.ResponseWriter, _ *netHTTP.Request) {
	authType, err := h.authController.GetAuthType()
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	httpUtil.StatusOK(w, auth.ConfigAuth{
		ApplicationAdminEnable: h.appConfig.GetEnableApplicationAdmin(),
		AuthType:               authType,
	})
}

// @Tags Auth
// @Description authenticate login by type!
// @ID authenticate login
// @Accept  json
// @Produce  json
// @Param Credentials body auth.Credentials true "auth info"
// @Success 200 {object} http.Response{content=string} "STATUS OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 403 {object} http.Response{content=string} "STATUS FORBIDDEN"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/auth/authenticate [post]
func (h *Handler) AuthByType(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	credentials, err := h.getCredentials(r)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	response, err := h.authController.AuthByType(credentials)
	if err != nil {
		h.checkErrorsByAuthType(w, err)
		return
	}

	httpUtil.StatusOK(w, response)
}

func (h *Handler) getCredentials(r *netHTTP.Request) (*auth.Credentials, error) {
	credentials, err := h.authUseCases.NewCredentialsFromReadCloser(r.Body)
	if err != nil {
		return credentials, err
	}

	return credentials, nil
}

func (h *Handler) checkErrorsByAuthType(w netHTTP.ResponseWriter, err error) {
	switch h.appConfig.GetAuthType() {
	case authEnums.Horusec:
		h.checkLoginErrorsHorusec(w, err)
	case authEnums.Keycloak:
		httpUtil.StatusInternalServerError(w, err)
	case authEnums.Ldap:
		h.checkLoginErrorsLdap(w, err)
	default:
		httpUtil.StatusInternalServerError(w, err)
	}
}

func (h *Handler) checkLoginErrorsHorusec(w netHTTP.ResponseWriter, err error) {
	if err == errors.ErrorWrongEmailOrPassword || err == errors.ErrNotFoundRecords {
		httpUtil.StatusForbidden(w, errors.ErrorWrongEmailOrPassword)
		return
	}

	if err == errors.ErrorAccountEmailNotConfirmed || err == errors.ErrorUserAlreadyLogged {
		httpUtil.StatusForbidden(w, err)
		return
	}

	httpUtil.StatusInternalServerError(w, err)
}

func (h *Handler) checkLoginErrorsLdap(w netHTTP.ResponseWriter, err error) {
	if err == errors.ErrorUserDoesNotExist {
		httpUtil.StatusForbidden(w, errors.ErrorWrongEmailOrPassword)
		return
	}

	httpUtil.StatusInternalServerError(w, err)
}

// @Tags Auth
// @Description verify if request is valid!
// @ID authenticate request
// @Accept  json
// @Produce  json
// @Param AuthorizationData body auth.AuthorizationData true "authorization data"
// @Success 200 {object} http.Response{content=string} "STATUS OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/auth/authorize [post]
func (h *Handler) Authorize(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	authorizationData, err := h.getAuthorizationData(r)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	response, err := h.authController.AuthorizeByType(authorizationData)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, response)
}

func (h *Handler) getAuthorizationData(r *netHTTP.Request) (*auth.AuthorizationData, error) {
	authorizationData, err := h.authUseCases.NewAuthorizationDataFromReadCloser(r.Body)
	if err != nil {
		return nil, err
	}

	return authorizationData, nil
}

// @Tags Auth
// @Description get account by token and auth type!
// @ID get account id
// @Accept  json
// @Produce  json
// @Success 200 {object} http.Response{content=string} "STATUS OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 400 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/auth/account-id [get]
func (h *Handler) GetAccountIDByAuthType(w netHTTP.ResponseWriter, r *netHTTP.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		httpUtil.StatusBadRequest(w, errors.ErrorTokenCanNotBeEmpty)
		return
	}

	accountID, err := h.authController.GetAccountIDByAuthType(token)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, accountID)
}
