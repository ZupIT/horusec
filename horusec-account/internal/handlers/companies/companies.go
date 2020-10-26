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
	cacheRepository "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/cache"
	accountUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/account"
	accountController "github.com/ZupIT/horusec/horusec-account/internal/controller/account"
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
	companyUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/company"
	"github.com/ZupIT/horusec/development-kit/pkg/usecases/repositories"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	companiesController "github.com/ZupIT/horusec/horusec-account/internal/controller/companies"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
)

type Handler struct {
	companyController  companiesController.IController
	repositoryUseCases repositories.IRepository
	companyUseCases    companyUseCases.ICompany
	appConfig          app.IAppConfig
	accountController  accountController.IAccount
}

func NewHandler(databaseWrite SQL.InterfaceWrite, databaseRead SQL.InterfaceRead, cache cacheRepository.Interface,
	broker brokerLib.IBroker, appConfig app.IAppConfig) *Handler {
	return &Handler{
		companyController: companiesController.NewController(databaseWrite, databaseRead, broker, appConfig),
		accountController: accountController.NewAccountController(
			broker, databaseRead, databaseWrite, cache, accountUseCases.NewAccountUseCases(), appConfig),
		repositoryUseCases: repositories.NewRepositoryUseCases(),
		companyUseCases:    companyUseCases.NewCompanyUseCases(),
		appConfig:          appConfig,
	}
}

// @Tags Companies
// @Description create company!
// @ID create-company
// @Accept  json
// @Produce  json
// @Param Company body account.Company true "company info. If applicationAdmin is enable add field adminEmail"
// @Success 201 {object} http.Response{content=string} "CREATED"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 401 {object} http.Response{content=string} "UNAUTHORIZED"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies [post]
// @Security ApiKeyAuth
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
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

func (h *Handler) factoryGetCreateData(w http.ResponseWriter, r *http.Request) (
	*accountEntities.Company, uuid.UUID, error) {
	if h.appConfig.IsEnableApplicationAdmin() {
		if err := h.checkIfUserLoggedIsApplicationAdmin(r); err != nil {
			httpUtil.StatusForbidden(w, err)
			return nil, uuid.Nil, err
		}
		return h.getCreateDataApplicationAdmin(w, r)
	}

	return h.getCreateDataDefault(w, r)
}

func (h *Handler) checkIfUserLoggedIsApplicationAdmin(r *http.Request) error {
	accountID, err := jwt.GetAccountIDByJWTToken(r.Header.Get("Authorization"))
	if err != nil {
		return err
	}
	isApplicationAdmin, err := h.accountController.UserIsApplicationAdmin(accountID)
	if err != nil {
		return err
	}
	if !isApplicationAdmin {
		return errorsEnum.ErrorUserLoggedIsNotApplicationAdmin
	}
	return nil
}

func (h *Handler) getCreateDataDefault(w http.ResponseWriter, r *http.Request) (
	*accountEntities.Company, uuid.UUID, error) {
	company, err := h.companyUseCases.NewCompanyFromReadCloser(r.Body)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return nil, uuid.Nil, err
	}

	accountID, err := uuid.Parse(fmt.Sprintf("%v", r.Context().Value(authEnums.AccountID)))
	if err != nil {
		httpUtil.StatusUnauthorized(w, err)
		return nil, uuid.Nil, err
	}

	return company, accountID, nil
}

func (h *Handler) getCreateDataApplicationAdmin(
	w http.ResponseWriter, r *http.Request) (*accountEntities.Company, uuid.UUID, error) {
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

func (h *Handler) getAccountIDByEmail(w http.ResponseWriter, email string) (uuid.UUID, error) {
	accountID, err := h.accountController.GetAccountIDByEmail(email)
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
// @Param Company body account.Company true "company info"
// @Param companyID path string true "companyID of the company"
// @Success 200 {object} http.Response{content=string} "OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID} [patch]
// @Security ApiKeyAuth
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
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
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	companyID, _ := uuid.Parse(chi.URLParam(r, "companyID"))
	accountID, _ := uuid.Parse(fmt.Sprintf("%v", r.Context().Value(authEnums.AccountID)))
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
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	accountID, err := uuid.Parse(fmt.Sprintf("%v", r.Context().Value(authEnums.AccountID)))
	if err != nil {
		httpUtil.StatusUnauthorized(w, err)
		return
	}

	if companies, err := h.companyController.List(accountID); err != nil {
		httpUtil.StatusBadRequest(w, err)
	} else {
		httpUtil.StatusOK(w, companies)
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
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
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
func (h *Handler) UpdateAccountCompany(w http.ResponseWriter, r *http.Request) {
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

func (h *Handler) getUpdateAccountCompanyData(r *http.Request) (*roles.AccountCompany, error) {
	accountCompany, err := h.companyUseCases.NewAccountCompanyFromReadCLoser(r.Body)
	if err != nil {
		return nil, err
	}

	return h.setAccountCompanyIDs(r, accountCompany)
}

func (h *Handler) setAccountCompanyIDs(
	r *http.Request, accountCompany *roles.AccountCompany) (*roles.AccountCompany, error) {
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
// @Param InviteUser body account.InviteUser true "invite user info"
// @Param companyID path string true "companyID of the company"
// @Success 200 {object} http.Response{content=string} "OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 404 {object} http.Response{content=string} "NOT FOUND"
// @Failure 409 {object} http.Response{content=string} "CONFLICT"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/companies/{companyID}/roles [post]
// @Security ApiKeyAuth
func (h *Handler) InviteUser(w http.ResponseWriter, r *http.Request) {
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

func (h *Handler) getInviteUserRequestData(r *http.Request) (*accountEntities.InviteUser, error) {
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

func (h *Handler) checkDefaultErrors(err error, w http.ResponseWriter) {
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
func (h *Handler) GetAccounts(w http.ResponseWriter, r *http.Request) {
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
func (h *Handler) RemoveUser(w http.ResponseWriter, r *http.Request) {
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

func (h *Handler) getRemoveUserRequestData(r *http.Request) (*accountEntities.RemoveUser, error) {
	removeUser := &accountEntities.RemoveUser{}
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
