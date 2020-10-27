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
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/account" // [swagger-import]
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	accountUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/account"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	accountController "github.com/ZupIT/horusec/horusec-auth/internal/controller/account"
	"net/http"
)

type Handler struct {
	controller accountController.IAccount
	useCases   accountUseCases.IAccount
}

func NewHandler(databaseRead SQL.InterfaceRead, databaseWrite SQL.InterfaceWrite) *Handler {
	useCases := accountUseCases.NewAccountUseCases()
	return &Handler{
		controller: accountController.NewAccountController(databaseRead, databaseWrite, useCases),
		useCases:   useCases,
	}
}

func (h *Handler) Options(w http.ResponseWriter, _ *http.Request) {
	httpUtil.StatusNoContent(w)
}

// @Tags Account
// @Description Create a new account with keycloak data!
// @ID create-account-keycloak
// @Accept  json
// @Produce  json
// @Param KeycloakToken body account.KeycloakToken true "keycloak token info"
// @Success 200 {object} http.Response{content=string} "STATUS OK"
// @Success 201 {object} http.Response{content=string} "STATUS CREATED"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/account/create-account-from-keycloak [post]
func (h *Handler) CreateAccountFromKeycloak(w http.ResponseWriter, r *http.Request) {
	keyCloakToken, err := h.useCases.NewKeycloakTokenFromReadCloser(r.Body)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	if err := h.controller.CreateAccountFromKeycloak(keyCloakToken); err != nil {
		h.checkCreateAccountFromKeycloakErrors(w, err)
		return
	}

	httpUtil.StatusCreated(w, "account created")
}

func (h *Handler) checkCreateAccountFromKeycloakErrors(w http.ResponseWriter, err error) {
	if err == errors.ErrorEmailAlreadyInUse || err == errors.ErrorUsernameAlreadyInUse {
		httpUtil.StatusOK(w, "")
		return
	}

	httpUtil.StatusInternalServerError(w, err)
}
