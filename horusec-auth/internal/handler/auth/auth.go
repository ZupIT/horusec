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
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	netHTTP "net/http"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth"   // [swagger-import]
	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/http" // [swagger-import]
	authUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/auth"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	"github.com/ZupIT/horusec/horusec-auth/config/app"
	authController "github.com/ZupIT/horusec/horusec-auth/internal/controller/auth"
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
// @Router /api/auth/config [get]
func (h *Handler) Config(w netHTTP.ResponseWriter, _ *netHTTP.Request) {
	httpUtil.StatusOK(w, auth.ConfigAuth{
		ApplicationAdminEnable: h.appConfig.GetEnableApplicationAdmin(),
		AuthType:               h.appConfig.GetAuthType(),
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
		h.checkLoginErrors(w, err)
		return
	}

	httpUtil.StatusOK(w, response)
}

func (h *Handler) getCredentials(r *netHTTP.Request) (*dto.Credentials, error) {
	credentials, err := h.authUseCases.NewCredentialsFromReadCloser(r.Body)
	if err != nil {
		return credentials, err
	}

	return credentials, nil
}

func (h *Handler) checkLoginErrors(w netHTTP.ResponseWriter, err error) {
	switch h.appConfig.GetAuthType() {
	case authEnums.Horusec:
		h.checkLoginErrorsHorusec(w, err)
	case authEnums.Ldap:
		httpUtil.StatusInternalServerError(w, err)
	case authEnums.Keycloak:
		httpUtil.StatusInternalServerError(w, err)
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
