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

package dashboard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	dashboardEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/dashboard"
	dashboardController "github.com/ZupIT/horusec/horusec-analytic/internal/controllers/dashboard"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/gqlerrors"
	"github.com/stretchr/testify/assert"
)

func TestOptions(t *testing.T) {
	t.Run("should return status code 204 when options", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		handler := Handler{controller: controllerMock}
		r, _ := http.NewRequest(http.MethodOptions, "api/dashboard", nil)
		w := httptest.NewRecorder()

		handler.Options(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

func TestGetVulnerabilitiesByAuthor(t *testing.T) {
	t.Run("should return status code 200 success get vulnerabilities", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnerabilitiesByAuthor").Return(&graphql.Result{}, nil)

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?query={ analysis(initialDate: "+
			"\"2020-07-19T00:00:00Z\", finalDate: \"2020-07-21T00:00:00Z\"){ repositoryID companyID } "+
			"};page=1;size=2", nil)

		w := httptest.NewRecorder()

		handler.GetVulnDetails(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return status code 400 when something went wrong", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnerabilitiesByAuthor").Return(&graphql.Result{
			Errors: []gqlerrors.FormattedError{{
				Message: "test",
			}},
		}, nil)

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?query={ analysis(companyID: 1){a w e w}}", nil)

		w := httptest.NewRecorder()

		handler.GetVulnDetails(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("should return status code 400 when missing query", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnerabilitiesByAuthor").Return(&graphql.Result{}, nil)

		handler := Handler{controller: controllerMock}
		r, _ := http.NewRequest(http.MethodGet, "api/dashboard", nil)

		w := httptest.NewRecorder()

		handler.GetVulnDetails(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestGetCompanyTotalDevelopers(t *testing.T) {
	t.Run("should return status code 200 success get vulnerabilities", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetTotalDevelopers").Return(10, nil)

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetCompanyTotalDevelopers(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return status code 500 when something went wrong", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetTotalDevelopers").Return(0, errors.New("test"))

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetCompanyTotalDevelopers(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 422 when invalid request", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard", nil)
		w := httptest.NewRecorder()

		handler.GetCompanyTotalDevelopers(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
}

func TestGetRepositoryTotalDevelopers(t *testing.T) {
	t.Run("should return status code 200 success get vulnerabilities", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetTotalDevelopers").Return(10, nil)

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetRepositoryTotalDevelopers(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return status code 500 when something went wrong", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetTotalDevelopers").Return(0, errors.New("test"))

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetRepositoryTotalDevelopers(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 422 when invalid request", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard", nil)
		w := httptest.NewRecorder()

		handler.GetRepositoryTotalDevelopers(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
}

func TestGetCompanyTotalRepositories(t *testing.T) {
	t.Run("should return status code 200 success get vulnerabilities", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetTotalRepositories").Return(10, nil)

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetCompanyTotalRepositories(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return status code 500 when something went wrong", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetTotalRepositories").Return(10, errors.New("test"))

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetCompanyTotalRepositories(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 422 when invalid request", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard", nil)
		w := httptest.NewRecorder()

		handler.GetCompanyTotalRepositories(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
}

func TestGetRepositoryTotalRepositories(t *testing.T) {
	t.Run("should return status code 200 success get vulnerabilities", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetTotalRepositories").Return(10, nil)

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetRepositoryTotalRepositories(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return status code 500 when something went wrong", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetTotalRepositories").Return(0, errors.New("test"))

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetRepositoryTotalRepositories(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 422 when invalid request", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard", nil)
		w := httptest.NewRecorder()

		handler.GetRepositoryTotalRepositories(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
}

func TestGetCompanyVulnByDeveloper(t *testing.T) {
	t.Run("should return status code 200 success get vulnerabilities", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnByDeveloper").Return([]dashboardEntities.VulnByDeveloper{{}}, nil)

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetCompanyVulnByDeveloper(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return status code 500 when something went wrong", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnByDeveloper").Return([]dashboardEntities.VulnByDeveloper{{}}, errors.New("test"))

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetCompanyVulnByDeveloper(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 422 when invalid request", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard", nil)
		w := httptest.NewRecorder()

		handler.GetCompanyVulnByDeveloper(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
}

func TestGetRepositoryVulnByDeveloper(t *testing.T) {
	t.Run("should return status code 200 success get vulnerabilities", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnByDeveloper").Return([]dashboardEntities.VulnByDeveloper{{}}, nil)

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetRepositoryVulnByDeveloper(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return status code 500 when something went wrong", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnByDeveloper").Return([]dashboardEntities.VulnByDeveloper{{}}, errors.New("test"))

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetRepositoryVulnByDeveloper(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 422 when invalid request", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard", nil)
		w := httptest.NewRecorder()

		handler.GetRepositoryVulnByDeveloper(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
}

func TestGetCompanyVulnByLanguage(t *testing.T) {
	t.Run("should return status code 200 success get vulnerabilities", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnByLanguage").Return([]dashboardEntities.VulnByLanguage{{}}, nil)

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetCompanyVulnByLanguage(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return status code 500 when something went wrong", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnByLanguage").Return([]dashboardEntities.VulnByLanguage{{}}, errors.New("test"))

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetCompanyVulnByLanguage(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 422 when invalid request", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard", nil)
		w := httptest.NewRecorder()

		handler.GetCompanyVulnByLanguage(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
}

func TestGetRepositoryVulnByLanguage(t *testing.T) {
	t.Run("should return status code 200 success get vulnerabilities", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnByLanguage").Return([]dashboardEntities.VulnByLanguage{{}}, nil)

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetRepositoryVulnByLanguage(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return status code 500 when something went wrong", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnByLanguage").Return([]dashboardEntities.VulnByLanguage{{}}, errors.New("test"))

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetRepositoryVulnByLanguage(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 422 when invalid request", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard", nil)
		w := httptest.NewRecorder()

		handler.GetRepositoryVulnByLanguage(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
}

func TestGetCompanyVulnByRepository(t *testing.T) {
	t.Run("should return status code 200 success get vulnerabilities", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnByRepository").Return([]dashboardEntities.VulnByRepository{{}}, nil)

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetCompanyVulnByRepository(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return status code 500 when something went wrong", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnByRepository").Return([]dashboardEntities.VulnByRepository{{}}, errors.New("test"))

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetCompanyVulnByRepository(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 422 when invalid request", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard", nil)
		w := httptest.NewRecorder()

		handler.GetCompanyVulnByRepository(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
}

func TestGetRepositoryVulnByRepository(t *testing.T) {
	t.Run("should return status code 200 success get vulnerabilities", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnByRepository").Return([]dashboardEntities.VulnByRepository{{}}, nil)

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetRepositoryVulnByRepository(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return status code 500 when something went wrong", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnByRepository").Return([]dashboardEntities.VulnByRepository{{}}, errors.New("test"))

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetRepositoryVulnByRepository(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 422 when invalid request", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard", nil)
		w := httptest.NewRecorder()

		handler.GetRepositoryVulnByRepository(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
}

func TestGetCompanyVulnByTime(t *testing.T) {
	t.Run("should return status code 200 success get vulnerabilities", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnByTime").Return([]dashboardEntities.VulnByTime{{}}, nil)

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetCompanyVulnByTime(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return status code 500 when something went wrong", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnByTime").Return([]dashboardEntities.VulnByTime{{}}, errors.New("test"))

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetCompanyVulnByTime(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 422 when invalid request", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard", nil)
		w := httptest.NewRecorder()

		handler.GetCompanyVulnByTime(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
}

func TestGetRepositoryVulnByTime(t *testing.T) {
	t.Run("should return status code 200 success get vulnerabilities", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnByTime").Return([]dashboardEntities.VulnByTime{{}}, nil)

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetRepositoryVulnByTime(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return status code 500 when something went wrong", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnByTime").Return([]dashboardEntities.VulnByTime{{}}, errors.New("test"))

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetRepositoryVulnByTime(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 422 when invalid request", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard", nil)
		w := httptest.NewRecorder()

		handler.GetRepositoryVulnByTime(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
}

func TestGetCompanyVulnBySeverity(t *testing.T) {
	t.Run("should return status code 200 success get vulnerabilities", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnBySeverity").Return([]dashboardEntities.VulnBySeverity{{}}, nil)

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetCompanyVulnBySeverity(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return status code 500 when something went wrong", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnBySeverity").Return([]dashboardEntities.VulnBySeverity{{}}, errors.New("test"))

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetCompanyVulnBySeverity(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 422 when invalid request", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard", nil)
		w := httptest.NewRecorder()

		handler.GetCompanyVulnBySeverity(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
}

func TestGetRepositoryVulnBySeverity(t *testing.T) {
	t.Run("should return status code 200 success get vulnerabilities", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnBySeverity").Return([]dashboardEntities.VulnBySeverity{{}}, nil)

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetRepositoryVulnBySeverity(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("should return status code 500 when something went wrong", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		controllerMock.On("GetVulnBySeverity").Return([]dashboardEntities.VulnBySeverity{{}}, errors.New("test"))

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?finalDate=2006-01-02T15:04:05Z;initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.GetRepositoryVulnBySeverity(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("should return status code 422 when invalid request", func(t *testing.T) {
		controllerMock := &dashboardController.Mock{}

		handler := Handler{controller: controllerMock}

		r, _ := http.NewRequest(http.MethodGet, "api/dashboard?initialDate=2006-01-02T15:04:05Z", nil)
		w := httptest.NewRecorder()

		handler.GetRepositoryVulnBySeverity(w, r)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
}
