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

package webhook

import (
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/adapter"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/config"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/account"
	entitiesWebhook "github.com/ZupIT/horusec/development-kit/pkg/entities/webhook"
	EnumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	_ "gorm.io/driver/sqlite" // Required in gorm usage
	"net/http"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	_ = os.RemoveAll("tmp")
	_ = os.MkdirAll("tmp", 0750)
	m.Run()
	_ = os.RemoveAll("tmp")
}

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
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		conn := adapter.NewRepositoryRead().GetConnection()
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
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		conn := adapter.NewRepositoryRead().GetConnection()
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
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		conn := adapter.NewRepositoryRead().GetConnection()
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
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		conn := adapter.NewRepositoryRead().GetConnection()
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
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		conn := adapter.NewRepositoryRead().GetConnection()
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
		_ = os.Setenv(config.EnvRelationalDialect, "sqlite")
		_ = os.Setenv(config.EnvRelationalURI, "tmp/tmp-"+uuid.New().String()+".db")
		conn := adapter.NewRepositoryRead().GetConnection()
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
