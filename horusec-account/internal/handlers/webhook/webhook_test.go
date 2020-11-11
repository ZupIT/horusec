package webhook

import (
	"bytes"
	"context"
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/webhook"
	errorsEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	webhookUseCases "github.com/ZupIT/horusec/development-kit/pkg/usecases/webhook"
	webhookController "github.com/ZupIT/horusec/horusec-account/internal/controller/webhook"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHandler(t *testing.T) {
	assert.NotEmpty(t, NewHandler(&relational.MockWrite{}, &relational.MockRead{}))
}

func TestHandler_Options(t *testing.T) {
	t.Run("should return status created when everything it is ok", func(t *testing.T) {
		handler := NewHandler(&relational.MockWrite{}, &relational.MockRead{})

		r, _ := http.NewRequest(http.MethodOptions, "api/webhook", nil)
		w := httptest.NewRecorder()

		handler.Options(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
}

func TestHandler_Create(t *testing.T) {
	t.Run("should return status created when everything it is ok", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("Create").Return(uuid.New(), nil)
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		body := &webhook.Webhook{
			Description: "",
			URL:         "http://example.com",
			Method:      "POST",
			Headers:     []webhook.Headers{},
		}

		r, _ := http.NewRequest(http.MethodPost, "api/webhook/companyID/repositoryID", bytes.NewReader(body.ToBytes()))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Create(w, r)

		assert.Equal(t, http.StatusCreated, w.Code)
	})
	t.Run("should return status bad request when url is incorrect", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("Create").Return(uuid.New(), nil)
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		body := &webhook.Webhook{
			Description: "",
			URL:         "invalid url",
			Method:      "POST",
			Headers:     []webhook.Headers{},
		}

		r, _ := http.NewRequest(http.MethodPost, "api/webhook/companyID/repositoryID", bytes.NewReader(body.ToBytes()))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Create(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("should return status bad request when method is incorrect", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("Create").Return(uuid.New(), nil)
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		body := &webhook.Webhook{
			Description: "",
			URL:         "https://example.com",
			Method:      "GET",
			Headers:     []webhook.Headers{},
		}

		r, _ := http.NewRequest(http.MethodPost, "api/webhook/companyID/repositoryID", bytes.NewReader(body.ToBytes()))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Create(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("should return status bad request when companyID is incorrect", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("Create").Return(uuid.New(), nil)
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		body := &webhook.Webhook{
			Description: "",
			URL:         "https://example.com",
			Method:      "POST",
			Headers:     []webhook.Headers{},
		}

		r, _ := http.NewRequest(http.MethodPost, "api/webhook/companyID/repositoryID", bytes.NewReader(body.ToBytes()))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", "")
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Create(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("should return status bad request when repositoryID is incorrect", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("Create").Return(uuid.New(), nil)
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		body := &webhook.Webhook{
			Description: "",
			URL:         "https://example.com",
			Method:      "POST",
			Headers:     []webhook.Headers{},
		}

		r, _ := http.NewRequest(http.MethodPost, "api/webhook/companyID/repositoryID", bytes.NewReader(body.ToBytes()))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		ctx.URLParams.Add("repositoryID", "")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Create(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("should return status conflict already exists webhook to repository", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("Create").Return(uuid.Nil, errorsEnum.ErrorAlreadyExistsWebhookToRepository)
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		body := &webhook.Webhook{
			Description: "",
			URL:         "http://example.com",
			Method:      "POST",
			Headers:     []webhook.Headers{},
		}

		r, _ := http.NewRequest(http.MethodPost, "api/webhook/companyID/repositoryID", bytes.NewReader(body.ToBytes()))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Create(w, r)

		assert.Equal(t, http.StatusConflict, w.Code)
	})
	t.Run("should return status internal server error", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("Create").Return(uuid.Nil, errors.New("unexpected error"))
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		body := &webhook.Webhook{
			Description: "",
			URL:         "http://example.com",
			Method:      "POST",
			Headers:     []webhook.Headers{},
		}

		r, _ := http.NewRequest(http.MethodPost, "api/webhook/companyID/repositoryID", bytes.NewReader(body.ToBytes()))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Create(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestHandler_ListAll(t *testing.T) {
	t.Run("should return status ok when everything it is ok", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("ListAll").Return(&[]webhook.ResponseWebhook{
			{
				WebhookID:    uuid.New(),
				Description:  "",
				URL:          "http://example.com",
				Method:       "POST",
				Headers:      []webhook.Headers{},
				RepositoryID: uuid.New(),
				CompanyID:    uuid.New(),
			},
		}, nil)
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		r, _ := http.NewRequest(http.MethodGet, "api/webhook/companyID", nil)
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.ListAll(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})
	t.Run("should return status bad request when companyID is incorrect", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("ListAll").Return(&[]webhook.ResponseWebhook{
			{
				WebhookID:    uuid.New(),
				Description:  "",
				URL:          "http://example.com",
				Method:       "POST",
				Headers:      []webhook.Headers{},
				RepositoryID: uuid.New(),
				CompanyID:    uuid.New(),
			},
		}, nil)
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		r, _ := http.NewRequest(http.MethodGet, "api/webhook/companyID", nil)
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", "")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.ListAll(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("should return status internal server error when unexpected error", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("ListAll").Return(&[]webhook.ResponseWebhook{}, errors.New("unexpected error"))
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		r, _ := http.NewRequest(http.MethodGet, "api/webhook/companyID", nil)
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.ListAll(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestHandler_Update(t *testing.T) {
	t.Run("should return status no content when everything it is ok", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("Update").Return(nil)
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		body := &webhook.Webhook{
			Description: "",
			URL:         "http://example.com",
			Method:      "POST",
			Headers:     []webhook.Headers{},
		}

		r, _ := http.NewRequest(http.MethodPut, "api/webhook/companyID/repositoryID/webhookID", bytes.NewReader(body.ToBytes()))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		ctx.URLParams.Add("webhookID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Update(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
	t.Run("should return status bad request when url is incorrect", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("Update").Return(nil)
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		body := &webhook.Webhook{
			Description: "",
			URL:         "invalid url",
			Method:      "POST",
			Headers:     []webhook.Headers{},
		}

		r, _ := http.NewRequest(http.MethodPut, "api/webhook/companyID/repositoryID/webhookID", bytes.NewReader(body.ToBytes()))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		ctx.URLParams.Add("webhookID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Update(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("should return status bad request when method is incorrect", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("Update").Return(nil)
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		body := &webhook.Webhook{
			Description: "",
			URL:         "https://example.com",
			Method:      "GET",
			Headers:     []webhook.Headers{},
		}

		r, _ := http.NewRequest(http.MethodPut, "api/webhook/companyID/repositoryID/webhookID", bytes.NewReader(body.ToBytes()))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		ctx.URLParams.Add("webhookID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Update(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("should return status bad request when companyID is incorrect", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("Update").Return(nil)
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		body := &webhook.Webhook{
			Description: "",
			URL:         "https://example.com",
			Method:      "POST",
			Headers:     []webhook.Headers{},
		}

		r, _ := http.NewRequest(http.MethodPut, "api/webhook/companyID/repositoryID/webhookID", bytes.NewReader(body.ToBytes()))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", "")
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		ctx.URLParams.Add("webhookID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Update(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("should return status bad request when repositoryID is incorrect", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("Update").Return(nil)
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		body := &webhook.Webhook{
			Description: "",
			URL:         "https://example.com",
			Method:      "POST",
			Headers:     []webhook.Headers{},
		}

		r, _ := http.NewRequest(http.MethodPut, "api/webhook/companyID/repositoryID/webhookID", bytes.NewReader(body.ToBytes()))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		ctx.URLParams.Add("repositoryID", "")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Update(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("should return status not found when not exists webhook to update", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("Update").Return(errorsEnum.ErrNotFoundRecords)
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		body := &webhook.Webhook{
			Description: "",
			URL:         "http://example.com",
			Method:      "POST",
			Headers:     []webhook.Headers{},
		}

		r, _ := http.NewRequest(http.MethodPut, "api/webhook/companyID/repositoryID/webhookID", bytes.NewReader(body.ToBytes()))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		ctx.URLParams.Add("webhookID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Update(w, r)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
	t.Run("should return status conflict already exists webhook to repository", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("Update").Return(errorsEnum.ErrorAlreadyExistsWebhookToRepository)
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		body := &webhook.Webhook{
			Description: "",
			URL:         "http://example.com",
			Method:      "POST",
			Headers:     []webhook.Headers{},
		}

		r, _ := http.NewRequest(http.MethodPut, "api/webhook/companyID/repositoryID/webhookID", bytes.NewReader(body.ToBytes()))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		ctx.URLParams.Add("webhookID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Update(w, r)

		assert.Equal(t, http.StatusConflict, w.Code)
	})
	t.Run("should return status internal server error", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("Update").Return(errors.New("unexpected error"))
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		body := &webhook.Webhook{
			Description: "",
			URL:         "http://example.com",
			Method:      "POST",
			Headers:     []webhook.Headers{},
		}

		r, _ := http.NewRequest(http.MethodPut, "api/webhook/companyID/repositoryID/webhookID", bytes.NewReader(body.ToBytes()))
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		ctx.URLParams.Add("webhookID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Update(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestHandler_Remove(t *testing.T) {
	t.Run("should return status no content when everything it is ok", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("Remove").Return(nil)
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		r, _ := http.NewRequest(http.MethodDelete, "api/webhook/companyID/repositoryID/webhookID", nil)
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		ctx.URLParams.Add("webhookID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Remove(w, r)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})
	t.Run("should return bad request when webhookID is wrong", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("Remove").Return(nil)
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		r, _ := http.NewRequest(http.MethodDelete, "api/webhook/companyID/repositoryID/webhookID", nil)
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		ctx.URLParams.Add("webhookID", "")
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Remove(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("should return internal server error when unexpected error happen", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("Remove").Return(errorsEnum.ErrNotFoundRecords)
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		r, _ := http.NewRequest(http.MethodDelete, "api/webhook/companyID/repositoryID/webhookID", nil)
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		ctx.URLParams.Add("webhookID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Remove(w, r)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
	t.Run("should return internal server error when unexpected error happen", func(t *testing.T) {
		mockController := &webhookController.Mock{}
		mockController.On("Remove").Return(errors.New("unexpected error"))
		handler := &Handler{
			webhookController: mockController,
			webhookUseCases:   webhookUseCases.NewWebhookUseCases(),
		}

		r, _ := http.NewRequest(http.MethodDelete, "api/webhook/companyID/repositoryID/webhookID", nil)
		w := httptest.NewRecorder()
		ctx := chi.NewRouteContext()
		ctx.URLParams.Add("companyID", uuid.New().String())
		ctx.URLParams.Add("repositoryID", uuid.New().String())
		ctx.URLParams.Add("webhookID", uuid.New().String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))

		handler.Remove(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}