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

//
//func TestOptions(t *testing.T) {
//	t.Run("should return status code 204 when options", func(t *testing.T) {
//		handler := NewHandler(nil, nil, nil, nil, nil)
//
//		r, _ := http.NewRequest(http.MethodOptions, "api/account", nil)
//		w := httptest.NewRecorder()
//
//		handler.Options(w, r)
//
//		assert.Equal(t, http.StatusNoContent, w.Code)
//	})
//}
//
//func TestHandler_CreateAccountFromKeycloak(t *testing.T) {
//	t.Run("Should return 400 because body is empty", func(t *testing.T) {
//		controllerMock := &accountController.Mock{}
//
//		handler := &Handler{
//			controller: controllerMock,
//			useCases:   authUseCases.NewAuthUseCases(),
//		}
//
//		r, _ := http.NewRequest(http.MethodPost, "test", nil)
//		w := httptest.NewRecorder()
//
//		handler.CreateAccountFromKeycloak(w, r)
//
//		assert.Equal(t, http.StatusBadRequest, w.Code)
//	})
//
//	t.Run("Should return 400 because body is wrong", func(t *testing.T) {
//		controllerMock := &accountController.Mock{}
//
//		handler := &Handler{
//			controller: controllerMock,
//			useCases:   authUseCases.NewAuthUseCases(),
//		}
//
//		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader([]byte("invalid body")))
//		w := httptest.NewRecorder()
//
//		handler.CreateAccountFromKeycloak(w, r)
//
//		assert.Equal(t, http.StatusBadRequest, w.Code)
//	})
//
//	t.Run("Should return 200 because user already registred", func(t *testing.T) {
//		keycloak := &dto.KeycloakToken{
//			AccessToken: "Some token",
//		}
//
//		controllerMock := &accountController.Mock{}
//		controllerMock.On("CreateAccountFromKeycloak").Return(&dto.CreateAccountFromKeycloakResponse{
//			AccountID:          uuid.New(),
//			Username:           uuid.New().String(),
//			Email:              uuid.New().String(),
//			IsApplicationAdmin: false,
//		}, errorsEnum.ErrorUsernameAlreadyInUse)
//
//		handler := &Handler{
//			controller: controllerMock,
//			useCases:   authUseCases.NewAuthUseCases(),
//		}
//
//		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(keycloak.ToBytes()))
//		w := httptest.NewRecorder()
//
//		handler.CreateAccountFromKeycloak(w, r)
//
//		assert.Equal(t, http.StatusOK, w.Code)
//	})
//
//	t.Run("Should return 500 unexpected error", func(t *testing.T) {
//		keycloak := &dto.KeycloakToken{
//			AccessToken: "Some token",
//		}
//
//		controllerMock := &accountController.Mock{}
//		controllerMock.On("CreateAccountFromKeycloak").Return(&dto.CreateAccountFromKeycloakResponse{}, errors.New("unexpected error"))
//
//		handler := &Handler{
//			controller: controllerMock,
//			useCases:   authUseCases.NewAuthUseCases(),
//		}
//
//		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(keycloak.ToBytes()))
//		w := httptest.NewRecorder()
//
//		handler.CreateAccountFromKeycloak(w, r)
//
//		assert.Equal(t, http.StatusInternalServerError, w.Code)
//	})
//
//	t.Run("Should return 200 because new user login in system", func(t *testing.T) {
//		keycloak := &dto.KeycloakToken{
//			AccessToken: "Some token",
//		}
//
//		controllerMock := &accountController.Mock{}
//		controllerMock.On("CreateAccountFromKeycloak").Return(&dto.CreateAccountFromKeycloakResponse{
//			AccountID:          uuid.New(),
//			Username:           uuid.New().String(),
//			Email:              uuid.New().String(),
//			IsApplicationAdmin: false,
//		}, nil)
//
//		handler := &Handler{
//			controller: controllerMock,
//			useCases:   authUseCases.NewAuthUseCases(),
//		}
//
//		r, _ := http.NewRequest(http.MethodPost, "test", bytes.NewReader(keycloak.ToBytes()))
//		w := httptest.NewRecorder()
//
//		handler.CreateAccountFromKeycloak(w, r)
//
//		assert.Equal(t, http.StatusOK, w.Code)
//	})
//}
//
//func TestCreateAccount(t *testing.T) {
//	t.Run("should return status code 201 when created with success", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//
//		account := &authEntities.Account{Email: "test@test.com", Username: "test", Password: "Ch@ng3m3"}
//		mockWrite.On("Create").Return(&response.Response{})
//		brokerMock.On("Publish").Return(nil)
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(account.ToBytes()))
//		w := httptest.NewRecorder()
//
//		handler.CreateAccount(w, r)
//
//		assert.Equal(t, http.StatusCreated, w.Code)
//	})
//
//	t.Run("should return status code 500 when some wrong happens", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//
//		account := &authEntities.Account{Email: "test@test.com", Username: "test", Password: "Ch@ng3m3"}
//		mockWrite.On("Create").Return(&response.Response{})
//		brokerMock.On("Publish").Return(errors.New("test"))
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(account.ToBytes()))
//		w := httptest.NewRecorder()
//
//		handler.CreateAccount(w, r)
//
//		assert.Equal(t, http.StatusInternalServerError, w.Code)
//	})
//
//	t.Run("should return status code 400 when email already in use", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//
//		account := &authEntities.Account{Email: "test@test.com", Username: "test", Password: "Test"}
//		mockWrite.On("Create").Return(&response.Response{})
//		brokerMock.On("Publish").Return(errorsEnum.ErrorEmailAlreadyInUse)
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(account.ToBytes()))
//		w := httptest.NewRecorder()
//
//		handler.CreateAccount(w, r)
//
//		assert.Equal(t, http.StatusBadRequest, w.Code)
//	})
//
//	t.Run("should return status code 400 when invalid data", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//		account := &authEntities.Account{}
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(account.ToBytes()))
//		w := httptest.NewRecorder()
//
//		handler.CreateAccount(w, r)
//
//		assert.Equal(t, http.StatusBadRequest, w.Code)
//	})
//}
//
//func TestValidateEmail(t *testing.T) {
//	t.Run("should return status ok 303 email is validated", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//
//		account := &authEntities.Account{
//			IsConfirmed: false,
//		}
//
//		resp := &response.Response{}
//		conn, _ := gorm.Open("sqlite3", ":memory:")
//		mockRead.On("GetConnection").Return(conn)
//		mockRead.On("Find").Return(resp.SetData(account))
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		mockWrite.On("Update").Return(resp)
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account/", nil)
//		w := httptest.NewRecorder()
//
//		ctx := chi.NewRouteContext()
//		ctx.URLParams.Add("accountID", "85d08ec1-7786-4c2d-bf4e-5fee3a010315")
//		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
//
//		handler.ValidateEmail(w, r)
//
//		assert.Equal(t, 303, w.Code)
//	})
//
//	t.Run("should return status code 500 when something went wrong validating email", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//
//		resp := &response.Response{}
//		conn, _ := gorm.Open("sqlite3", ":memory:")
//		mockRead.On("GetConnection").Return(conn)
//		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		mockWrite.On("Update").Return(resp)
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account/", nil)
//		w := httptest.NewRecorder()
//
//		ctx := chi.NewRouteContext()
//		ctx.URLParams.Add("accountID", "85d08ec1-7786-4c2d-bf4e-5fee3a010315")
//		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
//
//		handler.ValidateEmail(w, r)
//
//		assert.Equal(t, http.StatusInternalServerError, w.Code)
//	})
//
//	t.Run("should return status code 400 when invalid request", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account/test", nil)
//		w := httptest.NewRecorder()
//
//		handler.ValidateEmail(w, r)
//
//		assert.Equal(t, http.StatusBadRequest, w.Code)
//	})
//}
//
//func TestSendResetPasswordCode(t *testing.T) {
//	t.Run("should return status code 204 when successful", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//		account := &authEntities.Account{}
//
//		resp := &response.Response{}
//		conn, _ := gorm.Open("sqlite3", ":memory:")
//		mockRead.On("GetConnection").Return(conn)
//		mockRead.On("Find").Return(resp.SetData(account))
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		cacheRepositoryMock.On("Set").Return(nil)
//		brokerMock.On("Publish").Return(nil)
//
//		data := &dto.ResetCodeData{Email: "test@test.com", Code: "123456"}
//		dataBytes, _ := json.Marshal(data)
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(dataBytes))
//		w := httptest.NewRecorder()
//
//		handler.SendResetPasswordCode(w, r)
//
//		assert.Equal(t, http.StatusNoContent, w.Code)
//	})
//
//	t.Run("should return 500 when something went wrong", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//		account := &authEntities.Account{}
//
//		resp := &response.Response{}
//		conn, _ := gorm.Open("sqlite3", ":memory:")
//		mockRead.On("GetConnection").Return(conn)
//		mockRead.On("Find").Return(resp.SetData(account))
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		cacheRepositoryMock.On("Set").Return(nil)
//		brokerMock.On("Publish").Return(errors.New("test"))
//
//		data := &dto.ResetCodeData{Email: "test@test.com", Code: "123456"}
//		dataBytes, _ := json.Marshal(data)
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(dataBytes))
//		w := httptest.NewRecorder()
//
//		handler.SendResetPasswordCode(w, r)
//
//		assert.Equal(t, http.StatusInternalServerError, w.Code)
//	})
//
//	t.Run("should return 204 when email not found", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//
//		resp := &response.Response{}
//		conn, _ := gorm.Open("sqlite3", ":memory:")
//		mockRead.On("GetConnection").Return(conn)
//		mockRead.On("Find").Return(resp.SetError(errorsEnum.ErrNotFoundRecords))
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		cacheRepositoryMock.On("Set").Return(nil)
//
//		data := &dto.ResetCodeData{Email: "test@test.com", Code: "123456"}
//		dataBytes, _ := json.Marshal(data)
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(dataBytes))
//		w := httptest.NewRecorder()
//
//		handler.SendResetPasswordCode(w, r)
//
//		assert.Equal(t, http.StatusNoContent, w.Code)
//	})
//
//	t.Run("should return 400 when invalid email", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//
//		data := &dto.EmailData{Email: "test"}
//		dataBytes, _ := json.Marshal(data)
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(dataBytes))
//		w := httptest.NewRecorder()
//
//		handler.SendResetPasswordCode(w, r)
//
//		assert.Equal(t, http.StatusBadRequest, w.Code)
//	})
//}
//
//func TestValidateResetPasswordCode(t *testing.T) {
//	t.Run("should return status code 200 when everything it is ok", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//		account := &authEntities.Account{}
//
//		resp := &response.Response{}
//		conn, _ := gorm.Open("sqlite3", ":memory:")
//		mockRead.On("GetConnection").Return(conn)
//		mockRead.On("Find").Once().Return(resp.SetData(account))
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{Value: []byte("123456")}, nil)
//		cacheRepositoryMock.On("Del").Return(nil)
//
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		mockWrite.On("Update").Return(resp)
//
//		resp2 := &response.Response{}
//		mockRead.On("Find").Return(resp2.SetData(nil))
//		mockWrite.On("Update").Return(resp)
//
//		data := &dto.ResetCodeData{Email: "test@test.com", Code: "123456"}
//		dataBytes, _ := json.Marshal(data)
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(dataBytes))
//		w := httptest.NewRecorder()
//
//		handler.ValidateResetPasswordCode(w, r)
//
//		assert.Equal(t, http.StatusOK, w.Code)
//	})
//
//	t.Run("should return status code 500 when getting data in database", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//
//		resp := &response.Response{}
//		conn, _ := gorm.Open("sqlite3", ":memory:")
//		mockRead.On("GetConnection").Return(conn)
//		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{Value: []byte("123456")}, nil)
//
//		data := &dto.ResetCodeData{Email: "test@test.com", Code: "123456"}
//		dataBytes, _ := json.Marshal(data)
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(dataBytes))
//		w := httptest.NewRecorder()
//
//		ctx := chi.NewRouteContext()
//		ctx.URLParams.Add("email", "test@test.com")
//		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
//
//		handler.ValidateResetPasswordCode(w, r)
//
//		assert.Equal(t, http.StatusInternalServerError, w.Code)
//	})
//
//	t.Run("should return status code 401 when invalid code", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//		account := &authEntities.Account{}
//
//		resp := &response.Response{}
//		conn, _ := gorm.Open("sqlite3", ":memory:")
//		mockRead.On("GetConnection").Return(conn)
//		mockRead.On("Find").Return(resp.SetData(account))
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{Value: []byte("2131231")}, nil)
//		cacheRepositoryMock.On("Del").Return(nil)
//
//		data := &dto.ResetCodeData{Email: "test@test.com", Code: "123456"}
//		dataBytes, _ := json.Marshal(data)
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(dataBytes))
//		w := httptest.NewRecorder()
//
//		ctx := chi.NewRouteContext()
//		ctx.URLParams.Add("email", "test@test.com")
//		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
//
//		handler.ValidateResetPasswordCode(w, r)
//
//		assert.Equal(t, http.StatusForbidden, w.Code)
//	})
//
//	t.Run("should return status code 400 when invalid email", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//
//		data := &dto.ResetCodeData{Email: "test", Code: "123456"}
//		dataBytes, _ := json.Marshal(data)
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader(dataBytes))
//		w := httptest.NewRecorder()
//
//		handler.ValidateResetPasswordCode(w, r)
//
//		assert.Equal(t, http.StatusBadRequest, w.Code)
//	})
//}
//
//func TestResetPassword(t *testing.T) {
//	t.Run("should return status code 204 when password is changed", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//		account := &authEntities.Account{
//			AccountID: uuid.New(),
//			Username:  "test",
//			Email:     "test@test.com",
//			Password:  "Other@Pass123",
//		}
//		account.SetPasswordHash()
//		token, _, _ := jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)).CreateToken(account, nil)
//
//		resp := &response.Response{}
//		conn, _ := gorm.Open("sqlite3", ":memory:")
//		mockRead.On("GetConnection").Return(conn)
//		mockRead.On("Find").Once().Return(resp.SetData(account))
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		mockWrite.On("Update").Return(resp)
//		passwordBytes, _ := json.Marshal("Ch@ng3m3")
//		cacheRepositoryMock.On("Del").Return(nil)
//
//		resp2 := &response.Response{}
//		mockRead.On("Find").Return(resp2.SetData(nil))
//		mockWrite.On("Update").Return(resp)
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account/", bytes.NewReader(passwordBytes))
//		w := httptest.NewRecorder()
//		r.Header.Add("X-Horusec-Authorization", token)
//
//		handler.ChangePassword(w, r.WithContext(context.WithValue(r.Context(), authEnums.AccountData, uuid.New().String())))
//
//		assert.Equal(t, http.StatusNoContent, w.Code)
//	})
//
//	t.Run("should return status code 500 when something went wrong", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//		account := &authEntities.Account{
//			AccountID: uuid.New(),
//			Username:  "test",
//			Email:     "test@test.com",
//		}
//		token, _, _ := jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)).CreateToken(account, nil)
//
//		resp := &response.Response{}
//		conn, _ := gorm.Open("sqlite3", ":memory:")
//		mockRead.On("GetConnection").Return(conn)
//		mockRead.On("Find").Return(resp.SetData(account))
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		mockWrite.On("Update").Return(resp.SetError(errors.New("test")))
//		passwordBytes, _ := json.Marshal("Ch@ng3m3")
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account/", bytes.NewReader(passwordBytes))
//		w := httptest.NewRecorder()
//		r.Header.Add("X-Horusec-Authorization", token)
//
//		handler.ChangePassword(w, r.WithContext(context.WithValue(r.Context(), authEnums.AccountData, uuid.New().String())))
//
//		assert.Equal(t, http.StatusInternalServerError, w.Code)
//	})
//
//	t.Run("should return status code 400 failed to parse password", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//		account := &authEntities.Account{
//			AccountID: uuid.New(),
//			Username:  "test",
//			Email:     "test@test.com",
//		}
//		token, _, _ := jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)).CreateToken(account, nil)
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account/", nil)
//		w := httptest.NewRecorder()
//		r.Header.Add("X-Horusec-Authorization", token)
//
//		handler.ChangePassword(w, r.WithContext(context.WithValue(r.Context(), authEnums.AccountData, uuid.New().String())))
//
//		assert.Equal(t, http.StatusBadRequest, w.Code)
//	})
//
//	t.Run("should return status code 401 when invalid token", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account/", nil)
//		w := httptest.NewRecorder()
//
//		handler.ChangePassword(w, r)
//
//		assert.Equal(t, http.StatusUnauthorized, w.Code)
//	})
//}
//
//func TestRenewToken(t *testing.T) {
//	t.Run("should return status 200 renewed token", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//		account := &authEntities.Account{
//			AccountID: uuid.New(),
//			Username:  "test",
//			Email:     "test@test.com",
//		}
//		token, _, _ := jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)).CreateToken(account, nil)
//
//		resp := &response.Response{}
//		conn, _ := gorm.Open("sqlite3", ":memory:")
//		mockRead.On("GetConnection").Return(conn)
//		mockRead.On("Find").Once().Return(resp.SetData(account))
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{Value: []byte("test")}, nil)
//		cacheRepositoryMock.On("Del").Return(nil)
//		cacheRepositoryMock.On("Set").Return(nil)
//
//		resp2 := &response.Response{}
//		mockRead.On("Find").Return(resp2.SetData(nil))
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader([]byte("test")))
//		w := httptest.NewRecorder()
//		r.Header.Add("X-Horusec-Authorization", token)
//
//		handler.RenewToken(w, r)
//
//		assert.Equal(t, http.StatusOK, w.Code)
//	})
//
//	t.Run("should return status 401 when something went wrong", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//		account := &authEntities.Account{
//			AccountID: uuid.New(),
//			Username:  "test",
//			Email:     "test@test.com",
//		}
//		token, _, _ := jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)).CreateToken(account, nil)
//
//		resp := &response.Response{}
//		conn, _ := gorm.Open("sqlite3", ":memory:")
//		mockRead.On("GetConnection").Return(conn)
//		mockRead.On("Find").Return(resp.SetData(account))
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		cacheRepositoryMock.On("Get").Return(&entityCache.Cache{Value: []byte(account.AccountID.String())}, errors.New("test"))
//		cacheRepositoryMock.On("Del").Return(nil)
//		cacheRepositoryMock.On("Set").Return(nil)
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account", bytes.NewReader([]byte("test")))
//		w := httptest.NewRecorder()
//		r.Header.Add("X-Horusec-Authorization", token)
//
//		handler.RenewToken(w, r)
//
//		assert.Equal(t, http.StatusUnauthorized, w.Code)
//	})
//
//	t.Run("should return status 401 when missing authorization", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account", nil)
//		w := httptest.NewRecorder()
//
//		handler.RenewToken(w, r)
//
//		assert.Equal(t, http.StatusBadRequest, w.Code)
//	})
//
//	t.Run("should return status 401 when missing refresh token", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account", nil)
//		w := httptest.NewRecorder()
//		account := &authEntities.Account{
//			AccountID: uuid.New(),
//			Username:  "test",
//			Email:     "test@test.com",
//		}
//		token, _, _ := jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)).CreateToken(account, nil)
//		r.Header.Add("X-Horusec-Authorization", token)
//
//		handler.RenewToken(w, r)
//
//		assert.Equal(t, http.StatusBadRequest, w.Code)
//	})
//}
//
//func TestLogout(t *testing.T) {
//	account := &authEntities.Account{
//		IsConfirmed: false,
//		AccountID:   uuid.New(),
//		Email:       "test@test.com",
//		Password:    "test",
//		Username:    "test",
//	}
//
//	t.Run("should return status code 204 when successfully logout", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//
//		resp := &response.Response{}
//		conn, _ := gorm.Open("sqlite3", ":memory:")
//		mockRead.On("GetConnection").Return(conn)
//		mockRead.On("Find").Return(resp.SetData(account))
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		mockWrite.On("Update").Return(resp)
//		cacheRepositoryMock.On("Del").Return(nil)
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account/", nil)
//		w := httptest.NewRecorder()
//
//		token, _, _ := jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)).CreateToken(account, nil)
//		r.Header.Add("X-Horusec-Authorization", "Bearer "+token)
//
//		handler.Logout(w, r.WithContext(context.WithValue(r.Context(), authEnums.AccountData, uuid.New().String())))
//
//		assert.Equal(t, http.StatusNoContent, w.Code)
//	})
//
//	t.Run("should return status code 500 when something went wrong happened", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//
//		resp := &response.Response{}
//		conn, _ := gorm.Open("sqlite3", ":memory:")
//		mockRead.On("GetConnection").Return(conn)
//		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account/", nil)
//		w := httptest.NewRecorder()
//
//		token, _, _ := jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)).CreateToken(account, nil)
//		r.Header.Add("X-Horusec-Authorization", "Bearer "+token)
//
//		handler.Logout(w, r.WithContext(context.WithValue(r.Context(), authEnums.AccountData, uuid.New().String())))
//
//		assert.Equal(t, http.StatusInternalServerError, w.Code)
//	})
//
//	t.Run("should return status code 401  when invalid  or missing token", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account/", nil)
//		w := httptest.NewRecorder()
//
//		handler.Logout(w, r)
//
//		assert.Equal(t, http.StatusUnauthorized, w.Code)
//	})
//}
//
//func TestVerifyAlreadyInUse(t *testing.T) {
//	t.Run("should return status code 200 when not in use", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//
//		account := &authEntities.Account{}
//
//		resp := &response.Response{}
//		conn, _ := gorm.Open("sqlite3", ":memory:")
//		mockRead.On("GetConnection").Return(conn)
//		mockRead.On("Find").Return(resp.SetData(account))
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//
//		validateUnique := &dto.ValidateUnique{Email: "test@test.com", Username: "test"}
//		validateUniqueBytes, _ := json.Marshal(validateUnique)
//
//		r, _ := http.NewRequest(http.MethodPost, "api/account/", bytes.NewReader(validateUniqueBytes))
//		w := httptest.NewRecorder()
//
//		handler.VerifyAlreadyInUse(w, r)
//
//		assert.Equal(t, http.StatusOK, w.Code)
//	})
//
//	t.Run("should return status code 400 when username is already in use", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//
//		account := &authEntities.Account{Username: "test"}
//
//		resp := &response.Response{}
//		conn, _ := gorm.Open("sqlite3", ":memory:")
//		mockRead.On("GetConnection").Return(conn)
//		mockRead.On("Find").Return(resp.SetData(account))
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//
//		validateUnique := &dto.ValidateUnique{Email: "test@test.com", Username: "test"}
//		validateUniqueBytes, _ := json.Marshal(validateUnique)
//
//		r, _ := http.NewRequest(http.MethodPost, "api/account/", bytes.NewReader(validateUniqueBytes))
//		w := httptest.NewRecorder()
//
//		handler.VerifyAlreadyInUse(w, r)
//
//		assert.Equal(t, http.StatusBadRequest, w.Code)
//	})
//
//	t.Run("should return status code 400 when email is already in use", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//
//		account := &authEntities.Account{Email: "test@test.com"}
//
//		resp := &response.Response{}
//		conn, _ := gorm.Open("sqlite3", ":memory:")
//		mockRead.On("GetConnection").Return(conn)
//		mockRead.On("Find").Return(resp.SetData(account))
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//
//		validateUnique := &dto.ValidateUnique{Email: "test@test.com", Username: "test"}
//		validateUniqueBytes, _ := json.Marshal(validateUnique)
//
//		r, _ := http.NewRequest(http.MethodPost, "api/account/", bytes.NewReader(validateUniqueBytes))
//		w := httptest.NewRecorder()
//
//		handler.VerifyAlreadyInUse(w, r)
//
//		assert.Equal(t, http.StatusBadRequest, w.Code)
//	})
//
//	t.Run("should return status code 400 when invalid validate unique", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//
//		account := &authEntities.Account{Email: "test@test.com"}
//
//		resp := &response.Response{}
//		conn, _ := gorm.Open("sqlite3", ":memory:")
//		mockRead.On("GetConnection").Return(conn)
//		mockRead.On("Find").Return(resp.SetData(account))
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//
//		validateUnique := &dto.ValidateUnique{Email: "test", Username: "test"}
//		validateUniqueBytes, _ := json.Marshal(validateUnique)
//
//		r, _ := http.NewRequest(http.MethodPost, "api/account/", bytes.NewReader(validateUniqueBytes))
//		w := httptest.NewRecorder()
//
//		handler.VerifyAlreadyInUse(w, r)
//
//		assert.Equal(t, http.StatusBadRequest, w.Code)
//	})
//}
//
//func TestDeleteAccount(t *testing.T) {
//	t.Run("should return 204 when success delete account", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//		account := &authEntities.Account{
//			AccountID: uuid.New(),
//			Username:  "test",
//			Email:     "test@test.com",
//		}
//		token, _, _ := jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)).CreateToken(account, nil)
//
//		resp := &response.Response{}
//		conn, _ := gorm.Open("sqlite3", ":memory:")
//		mockRead.On("GetConnection").Return(conn)
//		mockRead.On("Find").Once().Return(resp.SetData(account))
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		mockWrite.On("Delete").Return(resp)
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account/", nil)
//		w := httptest.NewRecorder()
//		r.Header.Add("X-Horusec-Authorization", token)
//
//		handler.DeleteAccount(w, r.WithContext(context.WithValue(r.Context(), authEnums.AccountData, uuid.New().String())))
//
//		assert.Equal(t, http.StatusNoContent, w.Code)
//	})
//
//	t.Run("should return 500 when something went wrong", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//		account := &authEntities.Account{
//			AccountID: uuid.New(),
//			Username:  "test",
//			Email:     "test@test.com",
//		}
//		token, _, _ := jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)).CreateToken(account, nil)
//
//		resp := &response.Response{}
//		conn, _ := gorm.Open("sqlite3", ":memory:")
//		mockRead.On("GetConnection").Return(conn)
//		mockRead.On("Find").Once().Return(resp.SetData(account))
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		mockWrite.On("Delete").Return(resp.SetError(errors.New("test")))
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account/", nil)
//		w := httptest.NewRecorder()
//		r.Header.Add("X-Horusec-Authorization", token)
//
//		handler.DeleteAccount(w, r.WithContext(context.WithValue(r.Context(), authEnums.AccountData, uuid.New().String())))
//
//		assert.Equal(t, http.StatusInternalServerError, w.Code)
//	})
//
//	t.Run("should return 401 when invalid token", func(t *testing.T) {
//		brokerMock := &broker.Mock{}
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		cacheRepositoryMock := &cache.Mock{}
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(brokerMock, mockRead, mockWrite, cacheRepositoryMock, appConfig)
//		r, _ := http.NewRequest(http.MethodPost, "api/account/", nil)
//		w := httptest.NewRecorder()
//		r.Header.Add("X-Horusec-Authorization", "invalid token")
//
//		handler.DeleteAccount(w, r)
//
//		assert.Equal(t, http.StatusUnauthorized, w.Code)
//	})
//}
//
//func TestUpdateAccount(t *testing.T) {
//	t.Run("should return status code 200 when updated with success", func(t *testing.T) {
//		mockWrite := &relational.MockWrite{}
//		mockRead := &relational.MockRead{}
//
//		account := &authEntities.Account{AccountID: uuid.New(), Email: "test@test.com", Username: "test"}
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		mockRead.On("Find").Return(response.NewResponse(1, nil, account))
//		token, _, _ := jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)).CreateToken(account, nil)
//		mockWrite.On("Update").Return(&response.Response{})
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(nil, mockRead, mockWrite, nil, appConfig)
//		r, _ := http.NewRequest(http.MethodPatch, "api/account/update", bytes.NewReader(account.ToBytes()))
//		r.Header.Add("X-Horusec-Authorization", token)
//		w := httptest.NewRecorder()
//
//		handler.Update(w, r)
//
//		assert.Equal(t, http.StatusOK, w.Code)
//	})
//
//	t.Run("should return status code 401 when request does not have a token", func(t *testing.T) {
//		mockWrite := &relational.MockWrite{}
//		mockRead := &relational.MockRead{}
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		mockRead.On("Find").Return(response.NewResponse(0, nil, nil))
//
//		account := &authEntities.Account{AccountID: uuid.New(), Email: "test@test.com", Username: "test"}
//		mockWrite.On("Update").Return(&response.Response{})
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(nil, mockRead, mockWrite, nil, appConfig)
//		r, _ := http.NewRequest(http.MethodPatch, "api/account/update", bytes.NewReader(account.ToBytes()))
//		w := httptest.NewRecorder()
//
//		handler.Update(w, r)
//
//		assert.Equal(t, http.StatusUnauthorized, w.Code)
//	})
//
//	t.Run("should return status code 500 when fails get user", func(t *testing.T) {
//		mockWrite := &relational.MockWrite{}
//		mockRead := &relational.MockRead{}
//
//		account := &authEntities.Account{AccountID: uuid.New(), Email: "test@test.com", Username: "test"}
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		mockRead.On("Find").Return(response.NewResponse(0, errors.New("test"), nil))
//		token, _, _ := jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)).CreateToken(account, nil)
//		mockWrite.On("Update").Return(&response.Response{})
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(nil, mockRead, mockWrite, nil, appConfig)
//		r, _ := http.NewRequest(http.MethodPatch, "api/account/update", bytes.NewReader(account.ToBytes()))
//		r.Header.Add("X-Horusec-Authorization", token)
//		w := httptest.NewRecorder()
//
//		handler.Update(w, r)
//
//		assert.Equal(t, http.StatusInternalServerError, w.Code)
//	})
//
//	t.Run("should return status code 500 when update fails", func(t *testing.T) {
//		mockWrite := &relational.MockWrite{}
//		mockRead := &relational.MockRead{}
//		account := &authEntities.Account{AccountID: uuid.New(), Email: "test@test.com", Username: "test"}
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		mockRead.On("Find").Return(response.NewResponse(1, nil, account))
//
//		mockWrite.On("Update").Return(response.NewResponse(0, errors.New("test"), nil))
//		token, _, _ := jwt.NewJWT(env.GlobalAdminReadMock(0, nil, nil)).CreateToken(account, nil)
//
//		mockReadAdmin := env.GlobalAdminReadMock(0, nil, nil)
//		appConfig := app.NewConfig(mockReadAdmin)
//		handler := NewHandler(nil, mockRead, mockWrite, nil, appConfig)
//		r, _ := http.NewRequest(http.MethodPatch, "api/account/update", bytes.NewReader(account.ToBytes()))
//		r.Header.Add("X-Horusec-Authorization", token)
//		w := httptest.NewRecorder()
//
//		handler.Update(w, r)
//
//		assert.Equal(t, http.StatusInternalServerError, w.Code)
//	})
//}
