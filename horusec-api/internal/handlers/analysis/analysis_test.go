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

/*
{
  "id":"2807a8e2-3e69-426e-846b-2d2a4485d143",
  "repositoryID":"00000000-0000-0000-0000-000000000000",
  "repositoryName":"",
  "companyID":"00000000-0000-0000-0000-000000000000",
  "companyName":"",
  "status":"success",
  "errors":"",
  "createdAt":"2020-08-20T15:10:01.103499818-03:00",
  "finishedAt":"2020-08-20T15:10:16.231245518-03:00",
  "vulnerabilities":[
    {
      "line":"4",
      "column":"2",
      "confidence":"HIGH",
      "file":"/src/api/util/util.go",
      "code":"3: import (\n4: \t\"crypto/md5\"\n5: \t\"fmt\"\n",
      "details":"Blocklisted import crypto/md5: weak cryptographic primitive",
      "type":"",
      "vulnerableBelow":"",
      "version":"",
      "securityTool":"GoSec",
      "language":"Go",
      "severity":"MEDIUM",
      "commitAuthor":{
        "author":"Wilian Gabriel",
        "email":"wilian.silva@zup.com.br",
        "commitHash":"da439ca06ebed13b7d565dc88b43efe2f1ea7947",
        "message":"Change golang go-sec",
        "date":"2020-05-27 14:01:22 -0300"
      }
    },
    {
      "line":"23",
      "column":"7",
      "confidence":"HIGH",
      "file":"/src/api/util/util.go",
      "code":"22: func GetMD5(s string) string {\n23: \th := md5.New()\n24: \tio.WriteString(h, s) // #nohorus\n",
      "details":"Use of weak cryptographic primitive",
      "type":"",
      "vulnerableBelow":"",
      "version":"",
      "securityTool":"GoSec",
      "language":"Go",
      "severity":"NOSEC",
      "commitAuthor":{
        "author":"Wilian Gabriel",
        "email":"wilian.silva@zup.com.br",
        "commitHash":"da439ca06ebed13b7d565dc88b43efe2f1ea7947",
        "message":"Change golang go-sec",
        "date":"2020-05-27 14:01:22 -0300"
      }
    }
  ]
}
*/

import (
	"bytes"
	"context"
	"errors"
	apiEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/api"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
	t.Run("should return 400 when failed to get analysis ID", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		handler := NewHandler(mockRead, mockWrite)
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

		handler := NewHandler(mockRead, mockWrite)
		r, _ := http.NewRequest(http.MethodGet, "/api/analysis/", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("analysisID", "85d08ec1-7786-4c2d-bf4e-5fee3a010315")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Get(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return 200 when everything its ok", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}

		conn, err := gorm.Open("sqlite3", ":memory:")
		assert.NoError(t, err)
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(response.NewResponse(0, errorsEnum.ErrNotFoundRecords, &horusec.Analysis{}))

		handler := NewHandler(mockRead, mockWrite)
		r, _ := http.NewRequest(http.MethodGet, "/api/analysis/", nil)
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
		mockRead.On("Find").Return(response.NewResponse(0, nil, &horusec.Analysis{}))

		handler := NewHandler(mockRead, mockWrite)
		r, _ := http.NewRequest(http.MethodGet, "/api/analysis/", nil)
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

		handler := NewHandler(mockRead, mockWrite)
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

		handler := NewHandler(mockRead, mockWrite)
		r, _ := http.NewRequest(http.MethodDelete, "api/analysis", nil)
		w := httptest.NewRecorder()

		handler.Delete(w, r)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestPost(t *testing.T) {
	t.Run("Should return 201 when return success in create new analysis", func(t *testing.T) {
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

		handler := NewHandler(mockRead, mockWrite)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", bytes.NewReader(analysisData.ToBytes()))
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.RepositoryIDCtxKey, uuid.New())
		ctx = context.WithValue(ctx, middlewares.CompanyIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("Authorization", uuid.New().String())
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

		handler := NewHandler(mockRead, mockWrite)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", nil)
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.RepositoryIDCtxKey, uuid.New())
		ctx = context.WithValue(ctx, middlewares.CompanyIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("Authorization", uuid.New().String())
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

		handler := NewHandler(mockRead, mockWrite)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", bytes.NewReader([]byte("Wrong:Object")))
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.RepositoryIDCtxKey, uuid.New())
		ctx = context.WithValue(ctx, middlewares.CompanyIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("Authorization", uuid.New().String())
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

		handler := NewHandler(mockRead, mockWrite)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", bytes.NewReader(analysis.ToBytes()))
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.RepositoryIDCtxKey, uuid.New())
		ctx = context.WithValue(ctx, middlewares.CompanyIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("Authorization", uuid.New().String())
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

		handler := NewHandler(mockRead, mockWrite)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", bytes.NewReader(analysis.ToBytes()))
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.RepositoryIDCtxKey, uuid.New())
		ctx = context.WithValue(ctx, middlewares.CompanyIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("Authorization", uuid.New().String())
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

		handler := NewHandler(mockRead, mockWrite)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", bytes.NewReader(analysis.ToBytes()))
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.RepositoryIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("Authorization", uuid.New().String())
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

		handler := NewHandler(mockRead, mockWrite)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", bytes.NewReader(analysisData.ToBytes()))
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.CompanyIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("Authorization", uuid.New().String())
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

		handler := NewHandler(mockRead, mockWrite)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", bytes.NewReader(analysis.ToBytes()))
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.RepositoryIDCtxKey, uuid.New())
		ctx = context.WithValue(ctx, middlewares.CompanyIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("Authorization", uuid.New().String())
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

		handler := NewHandler(mockRead, mockWrite)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", bytes.NewReader(analysis.ToBytes()))
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.RepositoryIDCtxKey, uuid.New())
		ctx = context.WithValue(ctx, middlewares.CompanyIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("Authorization", uuid.New().String())
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

		handler := NewHandler(mockRead, mockWrite)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", bytes.NewReader(analysis.ToBytes()))
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.RepositoryIDCtxKey, uuid.New())
		ctx = context.WithValue(ctx, middlewares.CompanyIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("Authorization", uuid.New().String())
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

		handler := NewHandler(mockRead, mockWrite)
		r, _ := http.NewRequest(http.MethodPost, "api/analysis", bytes.NewReader(analysis.ToBytes()))
		ctx := r.Context()
		ctx = context.WithValue(ctx, middlewares.RepositoryIDCtxKey, uuid.New())
		ctx = context.WithValue(ctx, middlewares.CompanyIDCtxKey, uuid.New())
		r = r.WithContext(ctx)
		r.Header.Set("Authorization", uuid.New().String())
		w := httptest.NewRecorder()

		handler.Post(w, r)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}
