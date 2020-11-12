package webhook

import (
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	entitiesWebhook "github.com/ZupIT/horusec/development-kit/pkg/entities/webhook"
	EnumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite" // Required in gorm usage
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestMock(t *testing.T) {
	m := &Mock{}
	m.On("GetByRepositoryID").Return(&entitiesWebhook.Webhook{}, nil)
	m.On("GetByWebhookID").Return(&entitiesWebhook.Webhook{}, nil)
	m.On("GetAllByCompanyID").Return(&[]entitiesWebhook.ResponseWebhook{}, nil)
	m.On("Create").Return(nil)
	m.On("Update").Return(nil)
	m.On("Remove").Return(nil)
	_, err := m.GetAllByCompanyID(uuid.New())
	assert.NoError(t, err)
	_, err = m.GetByWebhookID(uuid.New())
	assert.NoError(t, err)
	_, err = m.GetByRepositoryID(uuid.New())
	assert.NoError(t, err)
	err = m.Create(&entitiesWebhook.Webhook{})
	assert.NoError(t, err)
	err = m.Update(&entitiesWebhook.Webhook{})
	assert.NoError(t, err)
	err = m.Remove(uuid.New())
	assert.NoError(t, err)
}

func TestNewWebhookRepository(t *testing.T) {
	assert.NotEmpty(t, NewWebhookRepository(&relational.MockRead{}, &relational.MockWrite{}))
}

func TestMock_GetByRepositoryID(t *testing.T) {
	t.Run("Should return error when get webhook by repository id", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		conn, err := gorm.Open("sqlite3", ":memory:")
		assert.NoError(t, err)
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(response.NewResponse(0, EnumErrors.ErrNotFoundRecords, nil))
		mockWrite := &relational.MockWrite{}
		r := NewWebhookRepository(mockRead, mockWrite)
		wh, err := r.GetByRepositoryID(uuid.New())
		assert.Error(t, err)
		assert.Empty(t, wh)
	})
	t.Run("Should not return error when get webhook by repository id", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		webhookData := &entitiesWebhook.Webhook{
			WebhookID:    uuid.New(),
			URL:          "http://example.com",
			Method:       http.MethodPost,
			Headers:      []entitiesWebhook.Headers{},
			RepositoryID: uuid.New(),
		}
		conn, err := gorm.Open("sqlite3", ":memory:")
		assert.NoError(t, err)
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(response.NewResponse(0, nil, webhookData))
		mockWrite := &relational.MockWrite{}
		r := NewWebhookRepository(mockRead, mockWrite)
		wh, err := r.GetByRepositoryID(uuid.New())
		assert.NoError(t, err)
		assert.Equal(t, wh, webhookData)
	})
}

func TestWebhook_GetByWebhookID(t *testing.T) {
	t.Run("Should return error when get webhook by webhook id", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		conn, err := gorm.Open("sqlite3", ":memory:")
		assert.NoError(t, err)
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(response.NewResponse(0, EnumErrors.ErrNotFoundRecords, nil))
		mockWrite := &relational.MockWrite{}
		r := NewWebhookRepository(mockRead, mockWrite)
		wh, err := r.GetByWebhookID(uuid.New())
		assert.Error(t, err)
		assert.Empty(t, wh)
	})
	t.Run("Should not return error when get webhook by webhook id", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		webhookData := &entitiesWebhook.Webhook{
			WebhookID:    uuid.New(),
			URL:          "http://example.com",
			Method:       http.MethodPost,
			Headers:      []entitiesWebhook.Headers{},
			RepositoryID: uuid.New(),
		}
		conn, err := gorm.Open("sqlite3", ":memory:")
		assert.NoError(t, err)
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(response.NewResponse(0, nil, webhookData))
		mockWrite := &relational.MockWrite{}
		r := NewWebhookRepository(mockRead, mockWrite)
		wh, err := r.GetByWebhookID(uuid.New())
		assert.NoError(t, err)
		assert.Equal(t, wh, webhookData)
	})
}

func TestWebhook_GetAllByCompanyID(t *testing.T) {
	t.Run("Should return error when get webhook by company id", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		conn, err := gorm.Open("sqlite3", ":memory:")
		assert.NoError(t, err)
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(response.NewResponse(0, EnumErrors.ErrNotFoundRecords, nil))
		mockWrite := &relational.MockWrite{}
		r := NewWebhookRepository(mockRead, mockWrite)
		wh, err := r.GetAllByCompanyID(uuid.New())
		assert.Error(t, err)
		assert.Empty(t, wh)
	})
	t.Run("Should not return error when get company by webhook id", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		webhookData := &[]entitiesWebhook.ResponseWebhook{
			{
				WebhookID:    uuid.New(),
				URL:          "http://example.com",
				Method:       http.MethodPost,
				Headers:      []entitiesWebhook.Headers{},
				RepositoryID: uuid.New(),
				Repository: account.Repository{
					Name: "repository",
				},
			},
		}
		conn, err := gorm.Open("sqlite3", ":memory:")
		assert.NoError(t, err)
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(response.NewResponse(0, nil, webhookData))
		mockWrite := &relational.MockWrite{}
		r := NewWebhookRepository(mockRead, mockWrite)
		wh, err := r.GetAllByCompanyID(uuid.New())
		assert.NoError(t, err)
		assert.Equal(t, wh, webhookData)
	})
}

func TestWebhook_Create(t *testing.T) {
	t.Run("Should return unexpected error when create webhook", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Create").Return(response.NewResponse(0, EnumErrors.ErrNotFoundRecords, nil))
		r := NewWebhookRepository(mockRead, mockWrite)
		err := r.Create(&entitiesWebhook.Webhook{})
		assert.Error(t, err)
	})
	t.Run("Should return not found when not return rows affected in create webhook", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Create").Return(response.NewResponse(0, nil, nil))
		r := NewWebhookRepository(mockRead, mockWrite)
		err := r.Create(&entitiesWebhook.Webhook{})
		assert.Error(t, err)
	})
	t.Run("Should return success when create webhook", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Create").Return(response.NewResponse(1, nil, nil))
		r := NewWebhookRepository(mockRead, mockWrite)
		err := r.Create(&entitiesWebhook.Webhook{})
		assert.NoError(t, err)
	})
}

func TestWebhook_Update(t *testing.T) {
	t.Run("Should return unexpected error when update webhook", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Update").Return(response.NewResponse(0, errors.New("unexpected error"), nil))
		r := NewWebhookRepository(mockRead, mockWrite)
		err := r.Update(&entitiesWebhook.Webhook{})
		assert.Error(t, err)
	})
	t.Run("Should return success when update webhook", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Update").Return(response.NewResponse(0, nil, nil))
		r := NewWebhookRepository(mockRead, mockWrite)
		err := r.Update(&entitiesWebhook.Webhook{})
		assert.NoError(t, err)
	})
}

func TestWebhook_Remove(t *testing.T) {
	t.Run("Should return unexpected error when remove webhook", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Delete").Return(response.NewResponse(0, errors.New("unexpected error"), nil))
		r := NewWebhookRepository(mockRead, mockWrite)
		err := r.Remove(uuid.New())
		assert.Error(t, err)
	})
	t.Run("Should return success when remove webhook", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockWrite := &relational.MockWrite{}
		mockWrite.On("Delete").Return(response.NewResponse(0, nil, nil))
		r := NewWebhookRepository(mockRead, mockWrite)
		err := r.Remove(uuid.New())
		assert.NoError(t, err)
	})
}
