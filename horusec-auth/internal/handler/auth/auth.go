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
	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/auth" // [swagger-import]
	authEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	authUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/auth"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	authController "github.com/ZupIT/horusec/horusec-auth/internal/controller/auth"
	"net/http"
)

type Handler struct {
	authUseCases   authUseCases.IUseCases
	authController authController.IController
}

func NewAuthHandler(postgresRead relational.InterfaceRead) *Handler {
	return &Handler{
		authUseCases:   authUseCases.NewAuthUseCases(),
		authController: authController.NewAuthController(postgresRead),
	}
}

func (h *Handler) Options(w http.ResponseWriter, _ *http.Request) {
	httpUtil.StatusNoContent(w)
}

// @Tags Auth
// @Description get actual type!
// @ID get type
// @Accept  json
// @Produce  json
// @Success 200 {object} http.Response{content=string} "STATUS OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Router /api/auth/auth-types [get]
func (h *Handler) AuthTypes(w http.ResponseWriter, _ *http.Request) {
	authType, err := h.authController.GetAuthType()
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	httpUtil.StatusOK(w, authType)
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
func (h *Handler) AuthByType(w http.ResponseWriter, r *http.Request) {
	credentials, err := h.getCredentials(r)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	response, err := h.authController.AuthByType(credentials)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, response)
}

func (h *Handler) getCredentials(r *http.Request) (*authEntities.Credentials, error) {
	credentials, err := h.authUseCases.NewCredentialsFromReadCloser(r.Body)
	if err != nil {
		return credentials, err
	}

	return credentials, nil
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
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
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

func (h *Handler) getAuthorizationData(r *http.Request) (*authEntities.AuthorizationData, error) {
	authorizationData, err := h.authUseCases.NewAuthorizationDataFromReadCloser(r.Body)
	if err != nil {
		return nil, err
	}

	return authorizationData, nil
}
