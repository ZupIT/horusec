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
	_ "github.com/ZupIT/horusec/development-kit/pkg/entities/account" // [swagger-import]
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	brokerLib "github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	"github.com/ZupIT/horusec/development-kit/pkg/services/jwt"
	accountUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/account"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	httpUtil "github.com/ZupIT/horusec/development-kit/pkg/utils/http"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-account/config/app"
	accountController "github.com/ZupIT/horusec/horusec-account/internal/controller/account"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
)

type Handler struct {
	controller accountController.IAccount
	useCases   accountUseCases.IAccount
}

func NewHandler(broker brokerLib.IBroker, databaseRead SQL.InterfaceRead,
	databaseWrite SQL.InterfaceWrite, cache cacheRepository.Interface, appConfig app.IAppConfig) *Handler {
	useCases := accountUseCases.NewAccountUseCases()
	return &Handler{
		controller: accountController.NewAccountController(
			broker, databaseRead, databaseWrite, cache, useCases, appConfig),
		useCases: useCases,
	}
}

func (h *Handler) Options(w http.ResponseWriter, _ *http.Request) {
	httpUtil.StatusNoContent(w)
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

// @Tags Account
// @Description Create a new account!
// @ID create-account
// @Accept  json
// @Produce  json
// @Param CreateAccount body account.CreateAccount true "create account info"
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

func (h *Handler) checkCreateAccountErrors(w http.ResponseWriter, err error) {
	if err == errors.ErrorEmailAlreadyInUse || err == errors.ErrorUsernameAlreadyInUse {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	httpUtil.StatusInternalServerError(w, err)
}

// @Tags Account
// @Description login into account!
// @ID login
// @Accept  json
// @Produce  json
// @Param LoginData body account.LoginData true "login data info"
// @Success 200 {object} http.Response{content=string} "OK"
// @Failure 400 {object} http.Response{content=string} "BAD REQUEST"
// @Failure 401 {object} http.Response{content=string} "UNAUTHORIZED"
// @Failure 500 {object} http.Response{content=string} "INTERNAL SERVER ERROR"
// @Router /api/account/login [post]
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	loginData, err := h.useCases.NewLoginFromReadCloser(r.Body)
	if err != nil {
		httpUtil.StatusBadRequest(w, err)
		return
	}

	response, err := h.controller.Login(loginData)
	if err != nil {
		h.checkLoginErrors(w, err)
		return
	}

	httpUtil.StatusOK(w, response)
}

func (h *Handler) checkLoginErrors(w http.ResponseWriter, err error) {
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
	accountID, password := h.getChangePasswordData(w, r)
	if accountID == uuid.Nil || password == "" {
		return
	}

	err := h.controller.ChangePassword(accountID, password)
	if err != nil {
		httpUtil.StatusInternalServerError(w, err)
		return
	}

	httpUtil.StatusNoContent(w)
}

func (h *Handler) getChangePasswordData(w http.ResponseWriter, r *http.Request) (uuid.UUID, string) {
	accountID, err := jwt.GetAccountIDByJWTToken(r.Header.Get("Authorization"))
	if err != nil {
		httpUtil.StatusUnauthorized(w, errors.ErrorDoNotHavePermissionToThisAction)
		return uuid.Nil, ""
	}

	password, err := h.useCases.NewPasswordFromReadCloser(r.Body)
	if err != nil {
		httpUtil.StatusBadRequest(w, errors.ErrorMissingOrInvalidPassword)
		return uuid.Nil, ""
	}

	return accountID, password
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
	accountID, err := jwt.GetAccountIDByJWTToken(r.Header.Get("Authorization"))
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
