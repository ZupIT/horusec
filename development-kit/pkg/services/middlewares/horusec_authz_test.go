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

package middlewares

//func setRequestAuthorizationHeader(req *http.Request) *http.Request {
//	account := &accountEntities.Account{
//		Email:     "test@test.com",
//		Username:  "test",
//		AccountID: uuid.New(),
//	}
//
//	token, _, _ := jwt.CreateToken(account, nil)
//	req.Header.Add("Authorization", "Bearer "+token)
//	return req
//}
//
//func TestIsMember(t *testing.T) {
//	t.Run("should return 200 when everything its alright", func(t *testing.T) {
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//
//		resp := response.Response{}
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		mockRead.On("Find").Return(resp.SetData(&roles.AccountCompany{}))
//
//		middleware := NewCompanyAuthzMiddleware(mockRead, mockWrite)
//		handler := middleware.IsCompanyMember(http.HandlerFunc(test.Handler))
//		req, _ := http.NewRequest("GET", "http://test", nil)
//		req = setRequestAuthorizationHeader(req)
//
//		rr := httptest.NewRecorder()
//		handler.ServeHTTP(rr, req)
//
//		assert.Equal(t, http.StatusOK, rr.Code)
//	})
//
//	t.Run("should return 403 when unable to find account", func(t *testing.T) {
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//
//		resp := response.Response{}
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
//
//		middleware := NewCompanyAuthzMiddleware(mockRead, mockWrite)
//		handler := middleware.IsCompanyMember(http.HandlerFunc(test.Handler))
//		req, _ := http.NewRequest("GET", "http://test", nil)
//		req = setRequestAuthorizationHeader(req)
//
//		rr := httptest.NewRecorder()
//		handler.ServeHTTP(rr, req)
//
//		assert.Equal(t, http.StatusForbidden, rr.Code)
//	})
//
//	t.Run("should return 401 when invalid jwt token", func(t *testing.T) {
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//
//		middleware := NewCompanyAuthzMiddleware(mockRead, mockWrite)
//		handler := middleware.IsCompanyMember(http.HandlerFunc(test.Handler))
//		req, _ := http.NewRequest("GET", "http://test", nil)
//
//		rr := httptest.NewRecorder()
//		handler.ServeHTTP(rr, req)
//
//		assert.Equal(t, http.StatusUnauthorized, rr.Code)
//	})
//}
//
//func TestIsAdmin(t *testing.T) {
//	t.Run("should return 200 when everything its alright", func(t *testing.T) {
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		accountCompany := &roles.AccountCompany{
//			AccountID: uuid.New(),
//			Role:      "admin",
//		}
//
//		resp := response.Response{}
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		mockRead.On("Find").Return(resp.SetData(accountCompany))
//
//		middleware := NewCompanyAuthzMiddleware(mockRead, mockWrite)
//		handler := middleware.IsCompanyAdmin(http.HandlerFunc(test.Handler))
//		req, _ := http.NewRequest("GET", "http://test", nil)
//		req = setRequestAuthorizationHeader(req)
//
//		rr := httptest.NewRecorder()
//		handler.ServeHTTP(rr, req)
//
//		assert.Equal(t, http.StatusOK, rr.Code)
//	})
//
//	t.Run("should return 403 when invalid role", func(t *testing.T) {
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//		accountCompany := &roles.AccountCompany{
//			AccountID: uuid.New(),
//			Role:      "member",
//		}
//
//		resp := response.Response{}
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		mockRead.On("Find").Return(resp.SetData(accountCompany))
//
//		middleware := NewCompanyAuthzMiddleware(mockRead, mockWrite)
//		handler := middleware.IsCompanyAdmin(http.HandlerFunc(test.Handler))
//		req, _ := http.NewRequest("GET", "http://test", nil)
//		req = setRequestAuthorizationHeader(req)
//
//		rr := httptest.NewRecorder()
//		handler.ServeHTTP(rr, req)
//
//		assert.Equal(t, http.StatusForbidden, rr.Code)
//	})
//
//	t.Run("should return 403 when find return error", func(t *testing.T) {
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//
//		resp := response.Response{}
//		mockRead.On("SetFilter").Return(&gorm.DB{})
//		mockRead.On("Find").Return(resp.SetError(errors.New("test")))
//
//		middleware := NewCompanyAuthzMiddleware(mockRead, mockWrite)
//		handler := middleware.IsCompanyAdmin(http.HandlerFunc(test.Handler))
//		req, _ := http.NewRequest("GET", "http://test", nil)
//		req = setRequestAuthorizationHeader(req)
//
//		rr := httptest.NewRecorder()
//		handler.ServeHTTP(rr, req)
//
//		assert.Equal(t, http.StatusForbidden, rr.Code)
//	})
//
//	t.Run("should return 401 when invalid jwt token", func(t *testing.T) {
//		mockRead := &relational.MockRead{}
//		mockWrite := &relational.MockWrite{}
//
//		middleware := NewCompanyAuthzMiddleware(mockRead, mockWrite)
//		handler := middleware.IsCompanyAdmin(http.HandlerFunc(test.Handler))
//		req, _ := http.NewRequest("GET", "http://test", nil)
//
//		rr := httptest.NewRecorder()
//		handler.ServeHTTP(rr, req)
//
//		assert.Equal(t, http.StatusUnauthorized, rr.Code)
//	})
//}
