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

package analysis

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	apiEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	"github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/test"
	"github.com/ZupIT/horusec/horusec-api/config/app"

	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	enumsHorusec "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/services/middlewares"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite" // Required in gorm usage

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/go-chi/chi"
	"github.com/stretchr/testify/assert"
)

func TestNewHandler(t *testing.T) {
	t.Run("should return a new analysis handler", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		result := NewHandler(mockRead, mockWrite, nil, nil)
		assert.NotNil(t, result)
	})
}

func TestOptions(t *testing.T) {
	t.Run("should return 204 when options", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		handler := NewHandler(mockRead, mockWrite, nil, nil)
		r, _ := http.NewRequest(http.MethodOptions, "api/analysis", nil)
		w := httptest.NewRecorder()

		handler.Options(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

func TestGet(t *testing.T) {
	t.Run("should return 400 when failed to get analysis ID", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		handler := NewHandler(mockRead, mockWrite, nil, nil)
		r, _ := http.NewRequest(http.MethodGet, "api/analysis", nil)
		w := httptest.NewRecorder()

		handler.Get(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return 500 when failed to get analysis", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		mockResponse := &response.Response{}
		conn, err := gorm.Open("sqlite3", ":memory:")
		assert.NoError(t, err)
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(mockResponse.SetError(errors.New("test")))

		handler := NewHandler(mockRead, mockWrite, nil, nil)
		r, _ := http.NewRequest(http.MethodGet, "/api/analysis/85d08ec1-7786-4c2d-bf4e-5fee3a010315", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("analysisID", "85d08ec1-7786-4c2d-bf4e-5fee3a010315")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Get(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 404 when failed to get analysis", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		mockResponse := &response.Response{}
		conn, err := gorm.Open("sqlite3", ":memory:")
		assert.NoError(t, err)
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(mockResponse.SetError(errorsEnum.ErrNotFoundRecords))

		handler := NewHandler(mockRead, mockWrite, nil, nil)
		r, _ := http.NewRequest(http.MethodGet, "/api/analysis/85d08ec1-7786-4c2d-bf4e-5fee3a010315", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("analysisID", "85d08ec1-7786-4c2d-bf4e-5fee3a010315")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Get(w, r)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("should return 200 when everything its ok", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		conn, err := gorm.Open("sqlite3", ":memory:")
		assert.NoError(t, err)
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(response.NewResponse(1, nil, test.CreateAnalysisMock()))

		handler := NewHandler(mockRead, mockWrite, nil, nil)
		r, _ := http.NewRequest(http.MethodGet, "/api/analysis/85d08ec1-7786-4c2d-bf4e-5fee3a010315", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("analysisID", "85d08ec1-7786-4c2d-bf4e-5fee3a010315")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Get(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestPut(t *testing.T) {
	t.Run("should return 405 when not allowed", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		handler := NewHandler(mockRead, mockWrite, nil, nil)
		r, _ := http.NewRequest(http.MethodPut, "api/analysis", nil)
		w := httptest.NewRecorder()

		handler.Put(w, r)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestDelete(t *testing.T) {
	t.Run("should return 405 when not allowed", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		handler := NewHandler(mockRead, mockWrite, nil, nil)
		r, _ := http.NewRequest(http.MethodDelete, "api/analysis", nil)
		w := httptest.NewRecorder()

		handler.Delete(w, r)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestPost(t *testing.T) {
	mockBroker := &broker.Mock{}
	config := &app.Config{
		DisabledBroker: false,
	}
	mockBroker.On("Publish").Return(nil)
	t.Run("Should return 201 when return success in create new analysis", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		conn, err := gorm.Open("sqlite3", ":memory:")
		assert.NoError(t, err)
		conn.Table("analysis").AutoMigrate(&horusec.Analysis{})
		conn.Table("analysis_vulnerabilities").AutoMigrate(&horusec.AnalysisVulnerabilities{})
		conn.Table("vulnerabilities").AutoMigrate(&horusec.Vulnerability{})
		conn.LogMode(true)
		resp := &response.Response{}

		mockWrite.On("StartTransaction").Return(mockWrite)
		mockWrite.On("Create").Return(resp)
		mockWrite.On("CommitTransaction").Return(resp)
		mockWrite.On("GetConnection").Return(conn)

		mockRead.On("Find").Return(resp)
		mockRead.On("SetFilter").Return(conn)

		analysisData := apiEntities.AnalysisData{
			Analysis:       test.CreateAnalysisMock(),
			RepositoryName: "",
		}

		handler := NewHandler(mockRead, mockWrite, mockBroker, config)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", bytes.NewReader(analysisData.ToBytes()))
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.RepositoryIDCtxKey, uuid.New())
		ctx = context.WithValue(ctx, middlewares.CompanyIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("X-Horusec-Authorization", uuid.New().String())
		w := httptest.NewRecorder()

		handler.Post(w, r)

		assert.Equal(t, http.StatusCreated, w.Code)
	})
	t.Run("Should return 400 when body is nil", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		handler := NewHandler(mockRead, mockWrite, mockBroker, config)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", nil)
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.RepositoryIDCtxKey, uuid.New())
		ctx = context.WithValue(ctx, middlewares.CompanyIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("X-Horusec-Authorization", uuid.New().String())
		w := httptest.NewRecorder()

		handler.Post(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("Should return 400 when body is wrong", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		handler := NewHandler(mockRead, mockWrite, mockBroker, config)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", bytes.NewReader([]byte("Wrong:Object")))
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.RepositoryIDCtxKey, uuid.New())
		ctx = context.WithValue(ctx, middlewares.CompanyIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("X-Horusec-Authorization", uuid.New().String())
		w := httptest.NewRecorder()

		handler.Post(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("Should return 400 when body is missing required fields in analysis", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		analysis := &apiEntities.AnalysisData{
			Analysis:       &horusec.Analysis{},
			RepositoryName: "",
		}

		handler := NewHandler(mockRead, mockWrite, mockBroker, config)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", bytes.NewReader(analysis.ToBytes()))
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.RepositoryIDCtxKey, uuid.New())
		ctx = context.WithValue(ctx, middlewares.CompanyIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("X-Horusec-Authorization", uuid.New().String())
		w := httptest.NewRecorder()

		handler.Post(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("Should return 400 when body is missing required fields in vulnerabilities", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		analysis := &apiEntities.AnalysisData{
			Analysis: &horusec.Analysis{
				Status:                  enumsHorusec.Success,
				CreatedAt:               time.Now(),
				FinishedAt:              time.Now(),
				AnalysisVulnerabilities: []horusec.AnalysisVulnerabilities{{}},
			},
			RepositoryName: "",
		}

		handler := NewHandler(mockRead, mockWrite, mockBroker, config)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", bytes.NewReader(analysis.ToBytes()))
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.RepositoryIDCtxKey, uuid.New())
		ctx = context.WithValue(ctx, middlewares.CompanyIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("X-Horusec-Authorization", uuid.New().String())
		w := httptest.NewRecorder()

		handler.Post(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("Should return 400 when companyID is not found", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		mockRead.On("Find").Return(resp)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		analysis := &apiEntities.AnalysisData{
			Analysis: &horusec.Analysis{
				Status:     enumsHorusec.Success,
				CreatedAt:  time.Now(),
				FinishedAt: time.Now(),
			},
			RepositoryName: "",
		}

		handler := NewHandler(mockRead, mockWrite, mockBroker, config)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", bytes.NewReader(analysis.ToBytes()))
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.RepositoryIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("X-Horusec-Authorization", uuid.New().String())
		w := httptest.NewRecorder()

		handler.Post(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("Should return 201 when repositoryID is not found", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}

		mockWrite.On("StartTransaction").Return(mockWrite)
		mockWrite.On("Create").Return(resp)
		mockWrite.On("CommitTransaction").Return(resp)

		mockRead.On("Find").Return(resp)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		analysisData := apiEntities.AnalysisData{
			Analysis: &horusec.Analysis{
				Status:     enumsHorusec.Success,
				CreatedAt:  time.Now(),
				FinishedAt: time.Now(),
			},
			RepositoryName: "",
		}

		handler := NewHandler(mockRead, mockWrite, mockBroker, config)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", bytes.NewReader(analysisData.ToBytes()))
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.CompanyIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("X-Horusec-Authorization", uuid.New().String())
		w := httptest.NewRecorder()

		handler.Post(w, r)

		assert.Equal(t, http.StatusCreated, w.Code)
	})
	t.Run("Should return 500 when return error create analysis", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}

		mockWrite.On("StartTransaction").Return(mockWrite)
		mockWrite.On("RollbackTransaction").Return(&response.Response{})
		mockWrite.On("Create").Return(resp.SetError(errors.New("create error")))

		resp = &response.Response{}

		mockRead.On("Find").Return(resp)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		analysis := &apiEntities.AnalysisData{
			Analysis: &horusec.Analysis{
				Status:     enumsHorusec.Success,
				CreatedAt:  time.Now(),
				FinishedAt: time.Now(),
			},
			RepositoryName: "",
		}

		handler := NewHandler(mockRead, mockWrite, mockBroker, config)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", bytes.NewReader(analysis.ToBytes()))
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.RepositoryIDCtxKey, uuid.New())
		ctx = context.WithValue(ctx, middlewares.CompanyIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("X-Horusec-Authorization", uuid.New().String())
		w := httptest.NewRecorder()

		handler.Post(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
	t.Run("Should return 500 when return error in transaction rollback", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}
		resp1 := &response.Response{}

		mockWrite.On("StartTransaction").Return(mockWrite)
		mockWrite.On("RollbackTransaction").Return(resp1.SetError(errors.New("rollback error")))
		mockWrite.On("Create").Return(resp.SetError(errors.New("create error")))

		resp = &response.Response{}

		mockRead.On("Find").Return(resp)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		analysis := &apiEntities.AnalysisData{
			Analysis: &horusec.Analysis{
				Status:     enumsHorusec.Success,
				CreatedAt:  time.Now(),
				FinishedAt: time.Now(),
			},
			RepositoryName: "",
		}

		handler := NewHandler(mockRead, mockWrite, mockBroker, config)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", bytes.NewReader(analysis.ToBytes()))
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.RepositoryIDCtxKey, uuid.New())
		ctx = context.WithValue(ctx, middlewares.CompanyIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("X-Horusec-Authorization", uuid.New().String())
		w := httptest.NewRecorder()

		handler.Post(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
	t.Run("Should return 500 when return error in transaction commit", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}

		mockWrite.On("StartTransaction").Return(mockWrite)
		mockWrite.On("CommitTransaction").Return(resp.SetError(errors.New("commit error")))
		mockWrite.On("Create").Return(&response.Response{})

		mockRead.On("Find").Return(&response.Response{})
		mockRead.On("SetFilter").Return(&gorm.DB{})

		analysis := &apiEntities.AnalysisData{
			Analysis: &horusec.Analysis{
				Status:     enumsHorusec.Success,
				CreatedAt:  time.Now(),
				FinishedAt: time.Now(),
			},
			RepositoryName: "",
		}

		handler := NewHandler(mockRead, mockWrite, mockBroker, config)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", bytes.NewReader(analysis.ToBytes()))
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.RepositoryIDCtxKey, uuid.New())
		ctx = context.WithValue(ctx, middlewares.CompanyIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("X-Horusec-Authorization", uuid.New().String())
		w := httptest.NewRecorder()

		handler.Post(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("Should return 404 when wrong token or missing repository name", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		resp := &response.Response{}

		mockWrite.On("StartTransaction").Return(mockWrite)
		mockWrite.On("RollbackTransaction").Return(&response.Response{})
		mockWrite.On("Create").Return(resp.SetError(errorsEnum.ErrNotFoundRecords))

		resp = &response.Response{}

		mockRead.On("Find").Return(resp)
		mockRead.On("SetFilter").Return(&gorm.DB{})

		analysis := &apiEntities.AnalysisData{
			Analysis: &horusec.Analysis{
				Status:     enumsHorusec.Success,
				CreatedAt:  time.Now(),
				FinishedAt: time.Now(),
			},
			RepositoryName: "",
		}

		handler := NewHandler(mockRead, mockWrite, mockBroker, config)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", bytes.NewReader(analysis.ToBytes()))
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.RepositoryIDCtxKey, uuid.New())
		ctx = context.WithValue(ctx, middlewares.CompanyIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("X-Horusec-Authorization", uuid.New().String())
		w := httptest.NewRecorder()

		handler.Post(w, r)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}
