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

package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api/dto"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	horusecEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	managementUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/management"
	"github.com/ZupIT/horusec/horusec-api/internal/controllers/management"
	"github.com/go-chi/chi"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHandler(t *testing.T) {
	t.Run("should return a new handler", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		result := NewHandler(mockRead, mockWrite)
		assert.NotNil(t, result)
	})
}

func TestOptions(t *testing.T) {
	t.Run("should return 204 when options", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		handler := NewHandler(mockRead, mockWrite)
		r, _ := http.NewRequest(http.MethodOptions, "api/analysis", nil)
		w := httptest.NewRecorder()

		handler.Options(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

func TestGet(t *testing.T) {
	t.Run("should return 200 when everything its ok", func(t *testing.T) {
		controllerMock := &management.Mock{}

		controllerMock.On("GetAllVulnManagementData").Return(dto.VulnManagement{}, nil)

		handler := Handler{managementController: controllerMock}
		r, _ := http.NewRequest(http.MethodGet, "api/management", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", "85d08ec1-7786-4c2d-bf4e-5fee3a010315")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Get(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 500 when something went wrong", func(t *testing.T) {
		controllerMock := &management.Mock{}

		controllerMock.On("GetAllVulnManagementData").Return(dto.VulnManagement{}, errors.New("test"))

		handler := Handler{managementController: controllerMock}
		r, _ := http.NewRequest(http.MethodGet, "api/management", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", "85d08ec1-7786-4c2d-bf4e-5fee3a010315")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Get(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 400 when missing or wrong repositoryID", func(t *testing.T) {
		controllerMock := &management.Mock{}

		controllerMock.On("GetAllVulnManagementData").Return(dto.VulnManagement{}, errors.New("test"))

		handler := Handler{managementController: controllerMock}
		r, _ := http.NewRequest(http.MethodGet, "api/management", nil)
		w := httptest.NewRecorder()

		handler.Get(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestPut(t *testing.T) {
	t.Run("should return 200 when everything its ok", func(t *testing.T) {
		controllerMock := &management.Mock{}

		controllerMock.On("Update").Return(&horusec.Vulnerability{}, nil)

		data := &dto.UpdateVulnManagementData{
			Status: horusecEnum.Approved,
			Type:   horusecEnum.RiskAccepted,
		}

		dataBytes, _ := json.Marshal(data)

		handler := Handler{managementController: controllerMock,
			managementUseCases: managementUseCases.NewManagementUseCases()}

		r, _ := http.NewRequest(http.MethodPut, "api/management", bytes.NewReader(dataBytes))
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("vulnerabilityID", "85d08ec1-7786-4c2d-bf4e-5fee3a010315")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Put(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return 500 when something went wrong", func(t *testing.T) {
		controllerMock := &management.Mock{}

		controllerMock.On("Update").Return(&horusec.Vulnerability{}, errors.New("test"))

		data := &dto.UpdateVulnManagementData{
			Status: horusecEnum.Approved,
			Type:   horusecEnum.RiskAccepted,
		}

		dataBytes, _ := json.Marshal(data)

		handler := Handler{managementController: controllerMock,
			managementUseCases: managementUseCases.NewManagementUseCases()}

		r, _ := http.NewRequest(http.MethodPut, "api/management", bytes.NewReader(dataBytes))
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("vulnerabilityID", "85d08ec1-7786-4c2d-bf4e-5fee3a010315")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Put(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 404 when not found vulnerability", func(t *testing.T) {
		controllerMock := &management.Mock{}

		controllerMock.On("Update").Return(&horusec.Vulnerability{}, errorsEnum.ErrNotFoundRecords)

		data := &dto.UpdateVulnManagementData{
			Status: horusecEnum.Approved,
			Type:   horusecEnum.RiskAccepted,
		}

		dataBytes, _ := json.Marshal(data)

		handler := Handler{managementController: controllerMock,
			managementUseCases: managementUseCases.NewManagementUseCases()}

		r, _ := http.NewRequest(http.MethodPut, "api/management", bytes.NewReader(dataBytes))
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("vulnerabilityID", "85d08ec1-7786-4c2d-bf4e-5fee3a010315")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Put(w, r)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("should return 400 when invalid request body", func(t *testing.T) {
		controllerMock := &management.Mock{}

		controllerMock.On("Update").Return(&horusec.Vulnerability{}, errorsEnum.ErrNotFoundRecords)

		handler := Handler{managementController: controllerMock,
			managementUseCases: managementUseCases.NewManagementUseCases()}

		r, _ := http.NewRequest(http.MethodPut, "api/management", bytes.NewReader([]byte("test")))
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("vulnerabilityID", "85d08ec1-7786-4c2d-bf4e-5fee3a010315")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Put(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return 400 when invalid vulnerability id", func(t *testing.T) {
		controllerMock := &management.Mock{}

		controllerMock.On("Update").Return(&horusec.Vulnerability{}, errorsEnum.ErrNotFoundRecords)

		handler := Handler{managementController: controllerMock,
			managementUseCases: managementUseCases.NewManagementUseCases()}

		data := &dto.UpdateVulnManagementData{
			Status: horusecEnum.Approved,
			Type:   horusecEnum.RiskAccepted,
		}

		dataBytes, _ := json.Marshal(data)

		r, _ := http.NewRequest(http.MethodPut, "api/management", bytes.NewReader(dataBytes))
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("vulnerabilityID", "test")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Put(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}
