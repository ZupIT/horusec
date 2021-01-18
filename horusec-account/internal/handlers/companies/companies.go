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

package companies

import (
	"fmt"
	netHttp "net/http"

	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account" // [swagger-import]
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account/dto"
	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/http" // [swagger-import]
	"github.com/ZupIT/horusec/development-kit/pkg/entities/roles"
	authEnums "github.com/ZupIT/horusec/development-kit/pkg/enums/auth"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	brokerLib "github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	authGrpc "github.com/ZupIT/horusec/development-kit/pkg/services/grpc/auth"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	"github.com/ZupIT/horusec/horusec-account/config/app"
	companiesController "github.com/ZupIT/horusec/horusec-account/internal/controller/companies"
	companyUseCases "github.com/ZupIT/horusec/horusec-account/internal/usecases/company"
	"github.com/ZupIT/horusec/horusec-account/internal/usecases/repositories"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
)

type Handler struct {
	companyController  companiesController.IController
	repositoryUseCases repositories.IRepository
	companyUseCases    companyUseCases.ICompany
	appConfig          app.IAppConfig
}

func NewHandler(databaseWrite SQL.InterfaceWrite, databaseRead SQL.InterfaceRead, broker brokerLib.IBroker,
	appConfig app.IAppConfig) *Handler {
	return &Handler{
		companyController:  companiesController.NewController(databaseWrite, databaseRead, broker, appConfig),
		repositoryUseCases: repositories.NewRepositoryUseCases(),
		companyUseCases:    companyUseCases.NewCompanyUseCases(),
		appConfig:          appConfig,
	}
}

// @Tags Companies
// @Description create company! If applicationAdmin is enable add field adminEmail in body
// @ID create-company
// @Accept  json
// @Produce  json
// @Param CreateCompany body account.Company true "create company info"
// @Success 201 {object} http.Response{content=string} "CREATED"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 401 {object} http.Response{content=string} "UNAUTHORIZED"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies [post]
// @Security ApiKeyAuth
func (h *Handler) Create(w netHttp.ResponseWriter, r *netHttp.Request) {
	company, accountID, err := h.factoryGetCreateData(w, r)
	if err != nil {
		return
	}

	newRepo, err := h.companyController.Create(accountID, company)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusCreated(w, newRepo)
}

func (h *Handler) factoryGetCreateData(w netHttp.ResponseWriter, r *netHttp.Request) (*account.Company, uuid.UUID, error) {
	if h.appConfig.IsApplicationAdminEnable() {
		return h.getCreateDataApplicationAdmin(w, r)
	}

	return h.getCreateDataDefault(w, r)
}

func (h *Handler) getCreateDataDefault(w netHttp.ResponseWriter, r *netHttp.Request) (
	*account.Company, uuid.UUID, error) {
	company, err := h.companyUseCases.NewCompanyFromReadCloser(r.Body)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return nil, uuid.Nil, err
	}

	accountData := r.Context().Value(authEnums.AccountData).(*authGrpc.GetAccountDataResponse)
	accountID, err := uuid.Parse(accountData.AccountID)
	if err != nil {
		httpUtil.StatusUnauthorized(w, err)
		return nil, uuid.Nil, err
	}

	return company, accountID, nil
}

func (h *Handler) getCreateDataApplicationAdmin(
	w netHttp.ResponseWriter, r *netHttp.Request) (*account.Company, uuid.UUID, error) {
	company, err := h.companyUseCases.NewCompanyApplicationAdminFromReadCloser(r.Body)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return nil, uuid.Nil, err
	}
	accountID, err := h.getAccountIDByEmail(w, company.AdminEmail)
	if err != nil {
		return nil, uuid.Nil, err
	}
	return company.ToCompany(), accountID, nil
}

func (h *Handler) getAccountIDByEmail(w netHttp.ResponseWriter, email string) (uuid.UUID, error) {
	accountID, err := h.companyController.GetAccountIDByEmail(email)
	if err != nil {
		if err == errorsEnum.ErrNotFoundRecords {
			httpUtil.StatusNotFound(w, err)
		} else {
			httpUtil.StatusInternalServerError(w, err)
		}
		return uuid.Nil, err
	}
	return accountID, nil
}

// @Tags Companies
// @Description update company!
// @ID update-company
// @Accept  json
// @Produce  json
// @Param UpdateCompany body account.Company true "update company info"
// @Param companyID path string true "companyID of the company"
// @Success 200 {object} http.Response{content=string} "OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID} [patch]
// @Security ApiKeyAuth
func (h *Handler) Update(w netHttp.ResponseWriter, r *netHttp.Request) {
	companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
	data, err := h.companyUseCases.NewCompanyFromReadCloser(r.Body)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	if company, err := h.companyController.Update(companyID, data); err != nil {
		httpUtil.StatusBadRequest(w, err)
	} else {
		httpUtil.StatusOK(w, company)
	}
}

// @Tags Companies
// @Description get company!
// @ID get-company
// @Accept  json
// @Produce  json
// @Param companyID path string true "companyID of the company"
// @Success 200 {object} http.Response{content=string} "OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID} [get]
// @Security ApiKeyAuth
func (h *Handler) Get(w netHttp.ResponseWriter, r *netHttp.Request) {
	companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
	accountID, _ := uuid.Parse(fmt.Sprintf("%v", r.Context().Value(authEnums.AccountData)))
	if company, err := h.companyController.Get(companyID, accountID); err != nil {
		httpUtil.StatusBadRequest(w, err)
	} else {
		httpUtil.StatusOK(w, company)
	}
}

// @Tags Companies
// @Description list companies!
// @ID list-companies
// @Accept  json
// @Produce  json
// @Success 200 {object} http.Response{content=string} "OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 401 {object} http.Response{content=string} "UNAUTHORIZED"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies [get]
// @Security ApiKeyAuth
func (h *Handler) List(w netHttp.ResponseWriter, r *netHttp.Request) {
	accountID, permissions, err := h.getRequestData(w, r)
	if err != nil {
		return
	}

	if companies, err := h.companyController.List(accountID, permissions); err != nil {
		httpUtil.StatusBadRequest(w, err)
	} else {
		httpUtil.StatusOK(w, companies)
	}
}

func (h *Handler) getRequestData(
	w netHttp.ResponseWriter, r *netHttp.Request) (uuid.UUID, []string, error) {
	accountData := r.Context().Value(authEnums.AccountData).(*authGrpc.GetAccountDataResponse)

	if accountID, err := uuid.Parse(accountData.AccountID); err != nil {
		httpUtil.StatusUnauthorized(w, err)
		return uuid.Nil, nil, err
	} else {
		return accountID, accountData.Permissions, nil
	}
}

// @Tags Companies
// @Description delete company!
// @ID delete-company
// @Accept  json
// @Produce  json
// @Param companyID path string true "companyID of the company"
// @Success 204 {object} http.Response{content=string} "NO CONTENT"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID} [delete]
// @Security ApiKeyAuth
func (h *Handler) Delete(w netHttp.ResponseWriter, r *netHttp.Request) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		httpUtil.StatusBadRequest(w, errorsEnum.ErrorInvalidCompanyID)
		return
	}

	if err := h.companyController.Delete(companyID); err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusNoContent(w)
}

// @Tags Companies
// @Description update account company!
// @ID update-account-company
// @Accept  json
// @Produce  json
// @Param AccountCompany body roles.AccountCompany true "account company info"
// @Param companyID path string true "companyID of the company"
// @Param accountID path string true "accountID of the account"
// @Success 200 {object} http.Response{content=string} "OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID}/roles/{accountID} [patch]
// @Security ApiKeyAuth
func (h *Handler) UpdateAccountCompany(w netHttp.ResponseWriter, r *netHttp.Request) {
	accountCompany, err := h.getUpdateAccountCompanyData(r)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	if err = h.companyController.UpdateAccountCompany(accountCompany); err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	httpUtil.StatusOK(w, "role updated")
}

func (h *Handler) getUpdateAccountCompanyData(r *netHttp.Request) (*roles.AccountCompany, error) {
	accountCompany, err := h.companyUseCases.NewAccountCompanyFromReadCLoser(r.Body)
	if err != nil {
		return nil, err
	}

	return h.setAccountCompanyIDs(r, accountCompany)
}

func (h *Handler) setAccountCompanyIDs(
	r *netHttp.Request, accountCompany *roles.AccountCompany) (*roles.AccountCompany, error) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		return nil, err
	}

	accountID, err := uuid.Parse(chi.URLParam(r, "accountID"))
	if err != nil {
		return nil, err
	}

	return accountCompany.SetCompanyAndAccountID(companyID, accountID), nil
}

// @Tags Companies
// @Description invite user to company!
// @ID invite-user
// @Accept  json
// @Produce  json
// @Param InviteUser body dto.InviteUser true "invite user info"
// @Param companyID path string true "companyID of the company"
// @Success 200 {object} http.Response{content=string} "OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 404 {object} http.Response{content=string} "NOT FOUND"
// @Failure 409 {object} http.Response{content=string} "CONFLICT"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID}/roles [post]
// @Security ApiKeyAuth
func (h *Handler) InviteUser(w netHttp.ResponseWriter, r *netHttp.Request) {
	inviteUser, err := h.getInviteUserRequestData(r)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	err = h.companyController.InviteUser(inviteUser)
	if err != nil {
		h.checkDefaultErrors(err, w)
		return
	}

	httpUtil.StatusNoContent(w)
}

func (h *Handler) getInviteUserRequestData(r *netHttp.Request) (*dto.InviteUser, error) {
	inviteUser, err := h.repositoryUseCases.NewInviteUserFromReadCloser(r.Body)
	if err != nil {
		return nil, err
	}

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		return nil, errorsEnum.ErrorInvalidCompanyID
	}

	return inviteUser.SetInviteUserCompanyID(companyID), nil
}

func (h *Handler) checkDefaultErrors(err error, w netHttp.ResponseWriter) {
	if err == errorsEnum.ErrNotFoundRecords {
		httpUtil.StatusNotFound(w, err)
		return
	}

	if err.Error() == errorsEnum.ErrorAlreadyExistingCompanyID {
		httpUtil.StatusConflict(w, errorsEnum.ErrorUserAlreadyInThisCompany)
		return
	}

	httpUtil.StatusInternalServerError(w, err)
}

// @Tags Companies
// @Description get all accounts in a company!
// @ID get-company-accounts
// @Accept  json
// @Produce  json
// @Param companyID path string true "companyID of the company"
// @Success 200 {object} http.Response{content=string} "OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID}/roles [get]
// @Security ApiKeyAuth
func (h *Handler) GetAccounts(w netHttp.ResponseWriter, r *netHttp.Request) {
	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		httpUtil.StatusBadRequest(w, errorsEnum.ErrorInvalidCompanyID)
		return
	}

	accounts, err := h.companyController.GetAllAccountsInCompany(companyID)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusOK(w, accounts)
}

// @Tags Companies
// @Description remove user from company!
// @ID remove-user
// @Accept  json
// @Produce  json
// @Param companyID path string true "companyID of the company"
// @Param accountID path string true "accountID of the account"
// @Success 204 {object} http.Response{content=string} "NO CONTENT"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 404 {object} http.Response{content=string} "NOT FOUND"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID}/roles/{accountID} [delete]
// @Security ApiKeyAuth
func (h *Handler) RemoveUser(w netHttp.ResponseWriter, r *netHttp.Request) {
	removeUser, err := h.getRemoveUserRequestData(r)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	err = h.companyController.RemoveUser(removeUser)
	if err != nil {
		h.checkDefaultErrors(err, w)
		return
	}

	httpUtil.StatusNoContent(w)
}

func (h *Handler) getRemoveUserRequestData(r *netHttp.Request) (*dto.RemoveUser, error) {
	removeUser := &dto.RemoveUser{}
	accountID, err := uuid.Parse(chi.URLParam(r, "accountID"))
	if err != nil {
		return nil, errorsEnum.ErrorInvalidAccountID
	}

	companyID, err := uuid.Parse(chi.URLParam(r, "companyID"))
	if err != nil {
		return nil, errorsEnum.ErrorInvalidCompanyID
	}

	return removeUser.SetAccountAndCompanyID(accountID, companyID), nil
}
