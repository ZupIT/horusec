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
	"encoding/json"
	netHttp "net/http"

	authGrpc "github.com/ZupIT/horusec/development-kit/pkg/services/grpc/auth"

	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/account" // [swagger-import]
	accountEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/dto"
	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/http" // [swagger-import]
	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	brokerLib "github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	"github.com/ZupIT/horusec/horusec-account/config/app"
	repositoriesController "github.com/ZupIT/horusec/horusec-account/internal/controller/repositories"
	"github.com/ZupIT/horusec/horusec-account/internal/usecases/repositories"
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
func (h *Handler) Create(w netHttp.ResponseWriter, r *netHttp.Request) {
	companyID, repository, err := h.getCreateRequestData(r)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	accountID, permissions := h.getAccountData(r)
	response, err := h.controller.Create(accountID, repository.SetCreateData(companyID), permissions)
	if err != nil {
		h.checkCreateRepositoryErrors(w, err)
		return
	}

	httpUtil.StatusCreated(w, response)
}

func (h *Handler) checkCreateRepositoryErrors(w netHttp.ResponseWriter, err error) {
	if err == errorsEnum.ErrorRepositoryNameAlreadyInUse || err == errorsEnum.ErrorInvalidLdapGroup {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	httpUtil.StatusInternalServerError(w, err)
}

func (h *Handler) getCreateRequestData(r *netHttp.Request) (uuid.UUID, *accountEntities.Repository, error) {
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
func (h *Handler) Update(w netHttp.ResponseWriter, r *netHttp.Request) {
	repositoryID, repository, err := h.getUpdateRequestData(r)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	_, permissions := h.getAccountData(r)
	response, err := h.controller.Update(repositoryID, repository, permissions)
	if err != nil {
		h.checkDefaultErrors(err, w)
		return
	}

	httpUtil.StatusOK(w, response)
}

func (h *Handler) getUpdateRequestData(r *netHttp.Request) (uuid.UUID, *accountEntities.Repository, error) {
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
func (h *Handler) Get(w netHttp.ResponseWriter, r *netHttp.Request) {
	repositoryID, err := uuid.Parse(chi.URLParam(r, "repositoryID"))
	if err != nil {
		httpUtil.StatusBadRequest(w, errorsEnum.ErrorInvalidRepositoryID)
		return
	}

	accountID, _ := h.getAccountData(r)
	repository, err := h.controller.Get(repositoryID, accountID)
	if err != nil {
		h.checkDefaultErrors(err, w)
		return
	}

	httpUtil.StatusOK(w, repository)
}

func (h *Handler) checkDefaultErrors(err error, w netHttp.ResponseWriter) {
	if err == errorsEnum.ErrNotFoundRecords {
		httpUtil.StatusNotFound(w, err)
		return
	}

	if err == errorsEnum.ErrorInvalidLdapGroup {
		httpUtil.StatusBadRequest(w, err)
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
func (h *Handler) List(w netHttp.ResponseWriter, r *netHttp.Request) {
	accountID, companyID, permissions, err := h.getRequestData(w, r)
	if err != nil {
		return
	}

	repositoryList, err := h.controller.List(accountID, companyID, permissions)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, repositoryList)
}

func (h *Handler) getRequestData(w netHttp.ResponseWriter, r *netHttp.Request) (uuid.UUID, uuid.UUID, []string, error) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil || companyID == uuid.Nil {
		httpUtil.StatusBadRequest(w, errorsEnum.ErrorInvalidCompanyID)
		return uuid.Nil, uuid.Nil, []string{}, errorsEnum.ErrorInvalidCompanyID
	}

	accountData := r.Context().Value(authEnums.AccountData).(*authGrpc.GetAccountDataResponse)
	accountID, err := uuid.Parse(accountData.AccountID)
	if err != nil {
		httpUtil.StatusUnauthorized(w, err)
		return uuid.Nil, uuid.Nil, nil, err
	}

	return accountID, companyID, accountData.Permissions, nil
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
func (h *Handler) Delete(w netHttp.ResponseWriter, r *netHttp.Request) {
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
func (h *Handler) UpdateAccountRepository(w netHttp.ResponseWriter, r *netHttp.Request) {
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

func (h *Handler) getAccountRepositoryRequestData(r *netHttp.Request) (*roles.AccountRepository, error) {
	accountRepository, err := h.useCases.NewAccountRepositoryFromReadCloser(r.Body)
	if err != nil {
		return nil, err
	}

	return h.getAccountRepositoryRequestID(r, accountRepository)
}

func (h *Handler) getAccountRepositoryRequestID(
	r *netHttp.Request, accountRepository *roles.AccountRepository) (*roles.AccountRepository, error) {
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
// @Param InviteUser body dto.InviteUser true "invite user info"
// @Param companyID path string true "companyID of the repository"
// @Param repositoryID path string true "repositoryID of the repository"
// @Success 204 {object} http.Response{content=string} "NO CONTENT"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 404 {object} http.Response{content=string} "NOT FOUND"
// @Failure 409 {object} http.Response{content=string} "CONFLICT"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID}/repositories/{repositoryID}/roles [post]
// @Security ApiKeyAuth
func (h *Handler) InviteUser(w netHttp.ResponseWriter, r *netHttp.Request) {
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

func (h *Handler) getInviteUserRequestData(r *netHttp.Request) (*dto.InviteUser, error) {
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
func (h *Handler) GetAccounts(w netHttp.ResponseWriter, r *netHttp.Request) {
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
func (h *Handler) RemoveUser(w netHttp.ResponseWriter, r *netHttp.Request) {
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

func (h *Handler) getRemoveUserRequestData(r *netHttp.Request) (*dto.RemoveUser, error) {
	removeUser := &dto.RemoveUser{}
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

func (h *Handler) getAccountData(r *netHttp.Request) (uuid.UUID, []string) {
	response := &authGrpc.GetAccountDataResponse{}

	accountData := r.Context().Value(authEnums.AccountData)
	bytes, _ := json.Marshal(accountData)
	_ = json.Unmarshal(bytes, &response)
	accountID, _ := uuid.Parse(response.AccountID)

	return accountID, response.Permissions
}
