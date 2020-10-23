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

package repositories

import (
	"fmt"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	"net/http"

	"github.com/ZupIT/horusec/horusec-account/config/app"

	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/account" // [swagger-import]
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/roles"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	brokerLib "github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	"github.com/ZupIT/horusec/development-kit/pkg/usecases/repositories"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	repositoriesController "github.com/ZupIT/horusec/horusec-account/internal/controller/repositories"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
)

type Handler struct {
	controller repositoriesController.IController
	useCases   repositories.IRepository
}

func NewRepositoryHandler(databaseWrite SQL.InterfaceWrite, databaseRead SQL.InterfaceRead,
	broker brokerLib.IBroker, appConfig app.IAppConfig) *Handler {
	return &Handler{
		controller: repositoriesController.NewController(databaseWrite, databaseRead, broker, appConfig),
		useCases:   repositories.NewRepositoryUseCases(),
	}
}

// @Tags Repositories
// @Description create repository!
// @ID create-repository
// @Accept  json
// @Produce  json
// @Param Repository body account.Repository true "repository info"
// @Param companyID path string true "companyID of the repository"
// @Success 201 {object} http.Response{content=string} "CREATED"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID}/repositories [post]
// @Security ApiKeyAuth
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	companyID, repository, err := h.getCreateRequestData(r)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	accountID, _ := uuid.Parse(fmt.Sprintf("%v", r.Context().Value(authEnums.AccountID)))
	response, err := h.controller.Create(accountID, repository.SetCreateData(companyID))
	if err != nil {
		h.checkCreateRepositoryErrors(w, err)
		return
	}

	httpUtil.StatusCreated(w, response)
}

func (h *Handler) checkCreateRepositoryErrors(w http.ResponseWriter, err error) {
	if err == errorsEnum.ErrorRepositoryNameAlreadyInUse {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	httpUtil.StatusInternalServerError(w, err)
}

func (h *Handler) getCreateRequestData(r *http.Request) (uuid.UUID, *accountEntities.Repository, error) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		return uuid.Nil, nil, errorsEnum.ErrorInvalidCompanyID
	}

	repository, err := h.useCases.NewRepositoryFromReadCloser(r.Body)
	return companyID, repository, err
}

// @Tags Repositories
// @Description update repository!
// @ID update-repository
// @Accept  json
// @Produce  json
// @Param Repository body account.Repository true "repository info"
// @Param companyID path string true "companyID of the repository"
// @Param repositoryID path string true "repositoryID of the repository"
// @Success 204 {object} http.Response{content=string} "NO CONTENT"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 404 {object} http.Response{content=string} "NOT FOUND"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID}/repositories/{repositoryID} [patch]
// @Security ApiKeyAuth
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	repositoryID, repository, err := h.getUpdateRequestData(r)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	response, err := h.controller.Update(repositoryID, repository)
	if err != nil {
		h.checkDefaultErrors(err, w)
		return
	}

	httpUtil.StatusOK(w, response)
}

func (h *Handler) getUpdateRequestData(r *http.Request) (uuid.UUID, *accountEntities.Repository, error) {
	repositoryID, err := uuid.Parse(chi.URLParam(r, "repositoryID"))
	if err != nil {
		return uuid.Nil, nil, errorsEnum.ErrorInvalidRepositoryID
	}

	repository, err := h.useCases.NewRepositoryFromReadCloser(r.Body)
	return repositoryID, repository, err
}

// @Tags Repositories
// @Description get repository!
// @ID get-repository
// @Accept  json
// @Produce  json
// @Param companyID path string true "companyID of the repository"
// @Param repositoryID path string true "repositoryID of the repository"
// @Success 200 {object} http.Response{content=string} "OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 404 {object} http.Response{content=string} "NOT FOUND"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID}/repositories/{repositoryID} [get]
// @Security ApiKeyAuth
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	repositoryID, err := uuid.Parse(chi.URLParam(r, "repositoryID"))
	if err != nil {
		httpUtil.StatusBadRequest(w, errorsEnum.ErrorInvalidRepositoryID)
		return
	}

	accountID, _ := uuid.Parse(fmt.Sprintf("%v", r.Context().Value(authEnums.AccountID)))
	repository, err := h.controller.Get(repositoryID, accountID)
	if err != nil {
		h.checkDefaultErrors(err, w)
		return
	}

	httpUtil.StatusOK(w, repository)
}

func (h *Handler) checkDefaultErrors(err error, w http.ResponseWriter) {
	if err == errorsEnum.ErrNotFoundRecords {
		httpUtil.StatusNotFound(w, err)
		return
	}

	if err.Error() == errorsEnum.ErrorAlreadyExistingRepositoryID {
		httpUtil.StatusConflict(w, errorsEnum.ErrorUserAlreadyInThisRepository)
		return
	}

	httpUtil.StatusInternalServerError(w, err)
}

// @Tags Repositories
// @Description list repositories!
// @ID list-repository
// @Accept  json
// @Produce  json
// @Param companyID path string true "companyID of the repository"
// @Success 200 {object} http.Response{content=string} "OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 404 {object} http.Response{content=string} "NOT FOUND"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID}/repositories [get]
// @Security ApiKeyAuth
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	companyID, accountID, err := h.getCompanyIDAndAccountIDToList(r)
	if err != nil {
		if err == errorsEnum.ErrorInvalidCompanyID {
			httpUtil.StatusBadRequest(w, err)
		} else {
			httpUtil.StatusUnauthorized(w, err)
		}
		return
	}
	repositoryList, err := h.controller.List(accountID, companyID)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}
	httpUtil.StatusOK(w, repositoryList)
}

func (h *Handler) getCompanyIDAndAccountIDToList(r *http.Request) (uuid.UUID, uuid.UUID, error) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil || companyID == uuid.Nil {
		return uuid.Nil, uuid.Nil, errorsEnum.ErrorInvalidCompanyID
	}
	accountID, err := uuid.Parse(fmt.Sprintf("%v", r.Context().Value(authEnums.AccountID)))
	return companyID, accountID, err
}

// @Tags Repositories
// @Description delete repository!
// @ID delete-repository
// @Accept  json
// @Produce  json
// @Param repositoryID path string true "repositoryID of the repository"
// @Param companyID path string true "companyID of the company"
// @Success 204 {object} http.Response{content=string} "NO CONTENT"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID}/repositories/{repositoryID} [delete]
// @Security ApiKeyAuth
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	repositoryID, err := uuid.Parse(chi.URLParam(r, "repositoryID"))
	if err != nil {
		httpUtil.StatusBadRequest(w, errorsEnum.ErrorInvalidCompanyID)
		return
	}

	if err := h.controller.Delete(repositoryID); err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusNoContent(w)
}

// @Tags Repositories
// @Description update account repository!
// @ID update-account-repository
// @Accept  json
// @Produce  json
// @Param AccountRepository body roles.AccountRepository true "account repository info"
// @Param companyID path string true "companyID of the repository"
// @Param repositoryID path string true "repositoryID of the repository"
// @Param accountID path string true "accountID of the repository"
// @Success 204 {object} http.Response{content=string} "NO CONTENT"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 404 {object} http.Response{content=string} "NOT FOUND"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID}/repositories/{repositoryID}/roles/{accountID} [patch]
// @Security ApiKeyAuth
func (h *Handler) UpdateAccountRepository(w http.ResponseWriter, r *http.Request) {
	accountRepository, err := h.getAccountRepositoryRequestData(r)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
	if err := h.controller.UpdateAccountRepository(companyID, accountRepository); err != nil {
		h.checkDefaultErrors(err, w)
		return
	}

	httpUtil.StatusNoContent(w)
}

func (h *Handler) getAccountRepositoryRequestData(r *http.Request) (*roles.AccountRepository, error) {
	accountRepository, err := h.useCases.NewAccountRepositoryFromReadCloser(r.Body)
	if err != nil {
		return nil, err
	}

	return h.getAccountRepositoryRequestID(r, accountRepository)
}

func (h *Handler) getAccountRepositoryRequestID(
	r *http.Request, accountRepository *roles.AccountRepository) (*roles.AccountRepository, error) {
	repositoryID, err := uuid.Parse(chi.URLParam(r, "repositoryID"))
	if err != nil {
		return nil, err
	}

	accountID, err := uuid.Parse(chi.URLParam(r, "accountID"))
	if err != nil {
		return nil, err
	}

	return accountRepository.SetRepositoryAndAccountID(repositoryID, accountID), nil
}

// @Tags Repositories
// @Description invite user to repository!
// @ID invite-user-repository
// @Accept  json
// @Produce  json
// @Param InviteUser body account.InviteUser true "invite user info"
// @Param companyID path string true "companyID of the repository"
// @Param repositoryID path string true "repositoryID of the repository"
// @Success 204 {object} http.Response{content=string} "NO CONTENT"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 404 {object} http.Response{content=string} "NOT FOUND"
// @Failure 409 {object} http.Response{content=string} "CONFLICT"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID}/repositories/{repositoryID}/roles [post]
// @Security ApiKeyAuth
func (h *Handler) InviteUser(w http.ResponseWriter, r *http.Request) {
	inviteUser, err := h.getInviteUserRequestData(r)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	err = h.controller.InviteUser(inviteUser)
	if err != nil {
		h.checkDefaultErrors(err, w)
		return
	}

	httpUtil.StatusNoContent(w)
}

func (h *Handler) getInviteUserRequestData(r *http.Request) (*accountEntities.InviteUser, error) {
	inviteUser, err := h.useCases.NewInviteUserFromReadCloser(r.Body)
	if err != nil {
		return nil, err
	}

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		return nil, errorsEnum.ErrorInvalidCompanyID
	}

	repositoryID, err := uuid.Parse(chi.URLParam(r, "repositoryID"))
	if err != nil {
		return nil, errorsEnum.ErrorInvalidRepositoryID
	}
	return inviteUser.SetInviteUserRepositoryAndCompanyID(companyID, repositoryID), nil
}

// @Tags Repositories
// @Description get all accounts in a repository!
// @ID get-repository-accounts
// @Accept  json
// @Produce  json
// @Param repositoryID path string true "repositoryID of the repository"
// @Param companyID path string true "companyID of the company"
// @Success 200 {object} http.Response{content=string} "OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID}/repositories/{repositoryID}/roles [get]
// @Security ApiKeyAuth
func (h *Handler) GetAccounts(w http.ResponseWriter, r *http.Request) {
	repositoryID, err := uuid.Parse(chi.URLParam(r, "repositoryID"))
	if err != nil {
		httpUtil.StatusBadRequest(w, errorsEnum.ErrorInvalidRepositoryID)
		return
	}

	accounts, err := h.controller.GetAllAccountsInRepository(repositoryID)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, accounts)
}

// @Tags Repositories
// @Description remove user from repository!
// @ID remove-user-repository
// @Accept  json
// @Produce  json
// @Param companyID path string true "companyID of the company"
// @Param repositoryID path string true "repositoryID of the repository"
// @Param accountID path string true "accountID of the account"
// @Success 204 {object} http.Response{content=string} "NO CONTENT"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 404 {object} http.Response{content=string} "NOT FOUND"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID}/repositories/{repositoryID}/roles/{accountID} [delete]
// @Security ApiKeyAuth
func (h *Handler) RemoveUser(w http.ResponseWriter, r *http.Request) {
	removeUser, err := h.getRemoveUserRequestData(r)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	err = h.controller.RemoveUser(removeUser)
	if err != nil {
		h.checkDefaultErrors(err, w)
		return
	}

	httpUtil.StatusNoContent(w)
}

func (h *Handler) getRemoveUserRequestData(r *http.Request) (*accountEntities.RemoveUser, error) {
	removeUser := &accountEntities.RemoveUser{}
	repositoryID, err := uuid.Parse(chi.URLParam(r, "repositoryID"))
	if err != nil {
		return nil, errorsEnum.ErrorInvalidRepositoryID
	}

	accountID, err := uuid.Parse(chi.URLParam(r, "accountID"))
	if err != nil {
		return nil, errorsEnum.ErrorInvalidAccountID
	}

	return removeUser.SetAccountAndRepositoryID(accountID, repositoryID), nil
}
