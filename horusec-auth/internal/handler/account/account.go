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
	"net/http"

	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	cacheRepository "github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/cache"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/auth/dto"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	brokerLib "github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	authUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/auth"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-auth/config/app"
	accountController "github.com/ZupIT/horusec/horusec-auth/internal/controller/account"
	"github.com/go-chi/chi"
	"github.com/google/uuid"

	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/account" // [swagger-import]
)

type Handler struct {
	controller accountController.IAccount
	useCases   authUseCases.IUseCases
}

func NewHandler(broker brokerLib.IBroker, databaseRead SQL.InterfaceRead,
	databaseWrite SQL.InterfaceWrite, cache cacheRepository.Interface, appConfig *app.Config) *Handler {
	return &Handler{
		controller: accountController.NewAccountController(broker, databaseRead, databaseWrite, cache, appConfig),
		useCases:   authUseCases.NewAuthUseCases(),
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
// @Success 200 {object} http.Response{content=account.CreateAccountFromKeycloakResponse{}} "STATUS OK"
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

	response, err := h.controller.CreateAccountFromKeycloak(keyCloakToken)
	if err != nil {
		h.checkCreateAccountFromKeycloakErrors(w, err, response)
		return
	}

	httpUtil.StatusOK(w, response)
}

func (h *Handler) checkCreateAccountFromKeycloakErrors(
	w http.ResponseWriter, err error, response *dto.CreateAccountFromKeycloakResponse) {
	if err == errors.ErrorEmailAlreadyInUse || err == errors.ErrorUsernameAlreadyInUse {
		httpUtil.StatusOK(w, response)
		return
	}

	httpUtil.StatusInternalServerError(w, err)
}

// @Tags Account
// @Description Create a new account!
// @ID create-account
// @Accept  json
// @Produce  json
// @Param CreateAccount body account.CreateAccount true "create account info"
// @Success 201 {object} http.Response{content=string} "STATUS CREATED"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/account/create-account [post]
func (h *Handler) CreateAccount(w http.ResponseWriter, r *http.Request) {
	account, err := h.useCases.NewAccountFromReadCloser(r.Body)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	if err := h.controller.CreateAccount(account); err != nil {
		h.checkCreateAccountErrors(w, err)
		return
	}

	httpUtil.StatusCreated(w, "account created")
}

func (h *Handler) checkCreateAccountErrors(w http.ResponseWriter, err error) {
	if err == errors.ErrorEmailAlreadyInUse || err == errors.ErrorUsernameAlreadyInUse {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	httpUtil.StatusInternalServerError(w, err)
}

// @Tags Account
// @Description validate email!
// @ID validate-email
// @Accept  json
// @Produce  json
// @Param accountID path string true "accountID of the account"
// @Success 200 {object} http.Response{content=string} "OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/account/validate/{accountID} [get]
func (h *Handler) ValidateEmail(w http.ResponseWriter, r *http.Request) {
	accountID, err := uuid.Parse(chi.URLParam(r, "accountID"))
	if err != nil {
		httpUtil.StatusBadRequest(w, errors.ErrorInvalidAccountID)
		return
	}

	err = h.controller.ValidateEmail(accountID)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	http.Redirect(w, r, env.GetHorusecManagerURL(), http.StatusSeeOther)
}

// @Tags Account
// @Description send reset password code!
// @ID reset-password-code
// @Accept  json
// @Produce  json
// @Param EmailData body account.EmailData true "reset password email info"
// @Success 204 {object} http.Response{content=string} "NO CONTENT"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/account/send-code [post]
func (h *Handler) SendResetPasswordCode(w http.ResponseWriter, r *http.Request) {
	emailData, err := h.useCases.NewEmailDataFromReadCloser(r.Body)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	err = h.controller.SendResetPasswordCode(emailData.Email)
	if err != nil {
		h.checkSendResetPasswordCodeErrors(w, err)
		return
	}

	httpUtil.StatusNoContent(w)
}

func (h *Handler) checkSendResetPasswordCodeErrors(w http.ResponseWriter, err error) {
	if err == errors.ErrNotFoundRecords {
		httpUtil.StatusNoContent(w)
		return
	}

	httpUtil.StatusInternalServerError(w, err)
}

// @Tags Account
// @Description validate reset password code!
// @ID validate-password-code
// @Accept  json
// @Produce  json
// @Param ResetCodeData body account.ResetCodeData true "reset password data info"
// @Success 204 {object} http.Response{content=string} "NO CONTENT"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 401 {object} http.Response{content=string} "UNAUTHORIZED"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/account/validate-code [post]
func (h *Handler) ValidateResetPasswordCode(w http.ResponseWriter, r *http.Request) {
	data, err := h.useCases.NewResetCodeDataFromReadCloser(r.Body)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	token, err := h.controller.VerifyResetPasswordCode(data)
	if err != nil {
		h.checkVerifyResetPasswordCodeErrors(w, err)
		return
	}

	httpUtil.StatusOK(w, token)
}

func (h *Handler) checkVerifyResetPasswordCodeErrors(w http.ResponseWriter, err error) {
	if err == errors.ErrorInvalidResetPasswordCode {
		httpUtil.StatusForbidden(w, errors.ErrorInvalidResetPasswordCode)
		return
	}

	httpUtil.StatusInternalServerError(w, err)
}

// @Tags Account
// @Description change password!
// @ID change-password
// @Accept  json
// @Produce  json
// @Param password body string true "new password"
// @Success 204 {object} http.Response{content=string} "NO CONTENT"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 401 {object} http.Response{content=string} "UNAUTHORIZED"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/account/change-password [post]
// @Security ApiKeyAuth
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	accountID, err := h.controller.GetAccountID(r.Header.Get("Authorization"))
	if err != nil || accountID == uuid.Nil {
		httpUtil.StatusUnauthorized(w, errors.ErrorDoNotHavePermissionToThisAction)
		return
	}

	password, err := h.useCases.NewPasswordFromReadCloser(r.Body)
	if err != nil {
		httpUtil.StatusBadRequest(w, errors.ErrorMissingOrInvalidPassword)
		return
	}
	h.executeChangePassword(w, accountID, password)
}

func (h *Handler) executeChangePassword(w http.ResponseWriter, accountID uuid.UUID, password string) {
	err := h.controller.ChangePassword(accountID, password)
	switch err {
	case errors.ErrorInvalidPassword:
		httpUtil.StatusConflict(w, err)
	case errors.ErrNotFoundRecords:
		httpUtil.StatusNotFound(w, err)
	case nil:
		httpUtil.StatusNoContent(w)
	default:
		httpUtil.StatusInternalServerError(w, err)
	}
}

// @Tags Account
// @Description renew token!
// @ID renew-token
// @Accept  json
// @Produce  json
// @Param refreshToken body string true "refresh token"
// @Success 200 {object} http.Response{content=string} "OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 401 {object} http.Response{content=string} "UNAUTHORIZED"
// @Router /api/account/renew-token [post]
// @Security ApiKeyAuth
func (h *Handler) RenewToken(w http.ResponseWriter, r *http.Request) {
	accessToken, refreshToken, err := h.getRenewTokenData(w, r)
	if err != nil {
		return
	}
	response, err := h.controller.RenewToken(refreshToken, accessToken)
	if err != nil {
		logger.LogError("renew token error -->", err)
		httpUtil.StatusUnauthorized(w, nil)
		return
	}

	httpUtil.StatusOK(w, response)
}

func (h *Handler) getRenewTokenData(w http.ResponseWriter, r *http.Request) (
	accessToken, refreshToken string, err error) {
	accessToken = r.Header.Get("Authorization")
	if accessToken == "" {
		httpUtil.StatusBadRequest(w, errors.ErrorEmptyAuthorizationToken)
		return "", "", errors.ErrorEmptyAuthorizationToken
	}

	refreshToken, err = h.useCases.NewRefreshTokenFromReadCloser(r.Body)
	if err != nil || refreshToken == "" {
		httpUtil.StatusBadRequest(w, errors.ErrorEmptyOrInvalidRefreshToken)
		return "", "", errors.ErrorEmptyOrInvalidRefreshToken
	}

	return accessToken, refreshToken, nil
}

// @Tags Account
// @Description logout!
// @ID logout
// @Accept  json
// @Produce  json
// @Success 200 {object} http.Response{content=string} "NO CONTENT"
// @Failure 401 {object} http.Response{content=string} "UNAUTHORIZED"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/account/logout [post]
// @Security ApiKeyAuth
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	accountID, err := h.controller.GetAccountID(r.Header.Get("Authorization"))
	if err != nil {
		httpUtil.StatusUnauthorized(w, errors.ErrorDoNotHavePermissionToThisAction)
		return
	}

	err = h.controller.Logout(accountID)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusNoContent(w)
}

// @Tags Account
// @Description Verify if email and username already in use!
// @ID validate-unique
// @Accept  json
// @Produce  json
// @Param ValidateUnique body account.ValidateUnique true "validate unique info"
// @Success 201 {object} http.Response{content=string} "STATUS CREATED"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/account/verify-already-used [post]
func (h *Handler) VerifyAlreadyInUse(w http.ResponseWriter, r *http.Request) {
	validateUnique, err := h.useCases.NewValidateUniqueFromReadCloser(r.Body)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	err = h.controller.VerifyAlreadyInUse(validateUnique)
	if err != nil {
		h.checkCreateAccountErrors(w, err)
		return
	}

	httpUtil.StatusOK(w, "")
}

// @Tags Account
// @Description Delete account and all permissions!
// @ID delete-account
// @Accept  json
// @Produce  json
// @Success 204 {object} http.Response{content=string} "NO CONTENT"
// @Failure 401 {object} http.Response{content=string} "UNAUTHORIZED"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/account/delete [delete]
// @Security ApiKeyAuth
func (h *Handler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	accountID, err := h.controller.GetAccountID(r.Header.Get("Authorization"))
	if err != nil {
		httpUtil.StatusUnauthorized(w, errors.ErrorDoNotHavePermissionToThisAction)
		return
	}

	if err = h.controller.DeleteAccount(accountID); err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusNoContent(w)
}

// @Tags Account
// @Description Update account username and/or email
// @ID update-account
// @Accept  json
// @Produce  json
// @Success 200 {object} http.Response{content=string} "OK"
// @Failure 401 {object} http.Response{content=string} "UNAUTHORIZED"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/account/delete [delete]
// @Security ApiKeyAuth
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	data, err := h.getAccountUpdateData(w, r)
	if err != nil {
		return
	}

	err = h.controller.UpdateAccount(data)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
	}

	httpUtil.StatusOK(w, "account updated")
}

func (h *Handler) getAccountUpdateData(w http.ResponseWriter, r *http.Request) (*auth.Account, error) {
	accountID, err := h.controller.GetAccountID(r.Header.Get("Authorization"))
	if err != nil {
		httpUtil.StatusUnauthorized(w, errors.ErrorDoNotHavePermissionToThisAction)
		return nil, errors.ErrorDoNotHavePermissionToThisAction
	}

	data, err := h.useCases.NewAccountUpdateFromReadCloser(r.Body)
	if err != nil {
		httpUtil.StatusBadRequest(w, errors.ErrorInvalidUpdateAccountData)
		return nil, errors.ErrorInvalidUpdateAccountData
	}

	data.AccountID = accountID

	return data, nil
}
