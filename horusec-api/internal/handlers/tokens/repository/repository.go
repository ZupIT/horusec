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

package repository

import (
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	netHttp "net/http"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"

	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/api" // [swagger-import]
	EnumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	tokensController "github.com/ZupIT/horusec/horusec-api/internal/controllers/tokens/repository"
	tokenUseCases "github.com/ZupIT/horusec/horusec-api/internal/usecases/tokens"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
)

type Handler struct {
	http.Interface
	controller    tokensController.IController
	tokenUseCases tokenUseCases.ITokenUseCases
}

func NewHandler(postgresRead relational.InterfaceRead, postgresWrite relational.InterfaceWrite) *Handler {
	return &Handler{
		controller:    tokensController.NewController(postgresRead, postgresWrite),
		tokenUseCases: tokenUseCases.NewTokenUseCases(),
	}
}

func (h *Handler) Options(w netHttp.ResponseWriter, r *netHttp.Request) {
	http.StatusNoContent(w)
}

// @Tags Tokens
// @Security ApiKeyAuth
// @Description Create a new repository token
// @ID repository-new-token
// @Accept  json
// @Produce  json
// @Param repositoryID path string true "repositoryID of the repository"
// @Param companyID path string true "companyID of the repository"
// @Param Token body api.Token true "token info"
// @Success 200 {object} http.Response{content=string} "CREATED"
// @Success 400 {object} http.Response{content=string} "BAD REQUEST"
// @Success 401 {object} http.Response{content=string} "UNAUTHORIZED"
// @Success 422 {object} http.Response{content=string} "UNPROCESSABLE ENTITY"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID}/repositories/{repositoryID}/tokens [post]
func (h *Handler) Post(w netHttp.ResponseWriter, r *netHttp.Request) {
	newToken, err := h.tokenUseCases.ValidateTokenRepository(r)
	if err != nil {
		http.StatusUnprocessableEntity(w, err)
		return
	}
	tokenKey, err := h.controller.CreateTokenRepository(newToken)
	if err != nil {
		http.StatusInternalServerError(w, err)
		return
	}

	http.StatusCreated(w, tokenKey)
}

// @Tags Tokens
// @Security ApiKeyAuth
// @Description Delete a repository token
// @ID repository-delete-token
// @Param repositoryID path string true "repositoryID of the repository"
// @Param companyID path string true "companyID of the repository"
// @Param tokenID path string true "ID of the token"
// @Success 204 {object} http.Response{content=string} "NO CONTENT"
// @Success 400 {object} http.Response{content=string} "BAD REQUEST"
// @Success 401 {object} http.Response{content=string} "UNAUTHORIZED"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID}/repositories/{repositoryID}/tokens/{tokenID} [delete]
func (h *Handler) Delete(w netHttp.ResponseWriter, r *netHttp.Request) {
	tokenID, err := uuid.Parse(chi.URLParam(r, "tokenID"))
	if err != nil || tokenID == uuid.Nil {
		http.StatusBadRequest(w, err)
		return
	}
	if err = h.controller.DeleteTokenRepository(tokenID); err != nil {
		if err == EnumErrors.ErrNotFoundRecords {
			http.StatusNotFound(w, err)
			return
		}
		http.StatusInternalServerError(w, err)
	} else {
		http.StatusNoContent(w)
	}
}

// @Tags Tokens
// @Security ApiKeyAuth
// @Description Delete a repository token
// @ID repository-get-all-token
// @Param repositoryID path string true "repositoryID of the repository"
// @Param companyID path string true "companyID of the repository"
// @Success 200 {object} http.Response{content=string} "OK"
// @Success 400 {object} http.Response{content=string} "BAD REQUEST"
// @Success 401 {object} http.Response{content=string} "UNAUTHORIZED"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID}/repositories/{repositoryID}/tokens [get]
func (h *Handler) Get(w netHttp.ResponseWriter, r *netHttp.Request) {
	repositoryID, err := uuid.Parse(chi.URLParam(r, "repositoryID"))
	if err != nil || repositoryID == uuid.Nil {
		http.StatusBadRequest(w, err)
		return
	}

	tokens, err := h.controller.GetAllTokenRepository(repositoryID)
	if err != nil {
		if err == EnumErrors.ErrNotFoundRecords {
			http.StatusOK(w, &[]api.Token{})
			return
		}
		http.StatusInternalServerError(w, err)
		return
	}

	http.StatusOK(w, tokens)
}
