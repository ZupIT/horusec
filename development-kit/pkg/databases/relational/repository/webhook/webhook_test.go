package webhook

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	entitiesWebhook "github.com/ZupIT/horusec/development-kit/pkg/entities/webhook"
	EnumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestNewWebhookRepository(t *testing.T) {
	assert.NotEmpty(t, NewWebhookRepository(&relational.MockRead{}, &relational.MockWrite{}))
}

func TestMock_GetByRepositoryID(t *testing.T) {
	t.Run("Should return error when get webhook by repository id", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockRead.On("SetFilter").Return(&gorm.DB{})
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
			Headers:      map[string]string{},
			RepositoryID: uuid.New(),
		}
		mockRead.On("SetFilter").Return(&gorm.DB{})
		mockRead.On("Find").Return(response.NewResponse(0, nil, webhookData))
		mockWrite := &relational.MockWrite{}
		r := NewWebhookRepository(mockRead, mockWrite)
		wh, err := r.GetByRepositoryID(uuid.New())
		assert.NoError(t, err)
		assert.Equal(t, wh, webhookData)
	})
}
