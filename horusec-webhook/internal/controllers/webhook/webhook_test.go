package webhook

import (
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/webhook"
	entitiesWebhook "github.com/ZupIT/horusec/development-kit/pkg/entities/webhook"
	EnumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/client"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/request"
	httpResponse "github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/response"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/test"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"

	_ "github.com/jinzhu/gorm/dialects/sqlite" // Required in gorm usage
)

func TestNewWebhookController(t *testing.T) {
	t.Run("Should call NewWebhookController", func(t *testing.T) {
		assert.NotEmpty(t, NewWebhookController(&relational.MockRead{}))
	})
}

func TestMock_DispatchRequest(t *testing.T) {
	conn, err := gorm.Open("sqlite3", ":memory:")
	assert.NoError(t, err)
	t.Run("Should return error because not found webhook in database", func(t *testing.T) {
		mockRead := &relational.MockRead{}
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(response.NewResponse(0, EnumErrors.ErrNotFoundRecords, nil))
		c := NewWebhookController(mockRead)
		err := c.DispatchRequest(test.CreateAnalysisMock())
		assert.NoError(t, err)
	})
	t.Run("Should return error because exists error in mount request", func(t *testing.T) {
		analysis := test.CreateAnalysisMock()
		webhookData := &entitiesWebhook.Webhook{
			WebhookID:    uuid.New(),
			URL:          "http://example.com",
			Method:       http.MethodPost,
			Headers:      []entitiesWebhook.Headers{},
			RepositoryID: analysis.RepositoryID,
		}
		mockRead := &relational.MockRead{}
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(response.NewResponse(0, nil, webhookData))
		mockRequest := &request.Mock{}
		mockRequest.On("Request").Return(&http.Request{}, errors.New("Error in mount request"))
		c := &Controller{
			databaseRead:      mockRead,
			webhookRepository: webhook.NewWebhookRepository(mockRead, nil),
			httpRequest:       mockRequest,
		}
		err := c.DispatchRequest(analysis)
		assert.Error(t, err)
	})
	t.Run("Should return error because exists error on execute do request", func(t *testing.T) {
		analysis := test.CreateAnalysisMock()
		webhookData := &entitiesWebhook.Webhook{
			WebhookID:    uuid.New(),
			URL:          "http://example.com",
			Method:       http.MethodPost,
			Headers:      []entitiesWebhook.Headers{},
			RepositoryID: analysis.RepositoryID,
		}
		mockRead := &relational.MockRead{}
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(response.NewResponse(0, nil, webhookData))
		mockRequest := &request.Mock{}
		mockRequest.On("Request").Return(&http.Request{}, nil)
		mockClient := &client.Mock{}
		mockClient.On("DoRequest").Return(httpResponse.NewHTTPResponse(&http.Response{}), errors.New("unexpected error"))
		c := &Controller{
			databaseRead:      mockRead,
			webhookRepository: webhook.NewWebhookRepository(mockRead, nil),
			httpRequest:       mockRequest,
			httpClient:        mockClient,
		}
		err := c.DispatchRequest(analysis)
		assert.Error(t, err)
	})
	t.Run("Should return error because request return err client side", func(t *testing.T) {
		analysis := test.CreateAnalysisMock()
		webhookData := &entitiesWebhook.Webhook{
			WebhookID:    uuid.New(),
			URL:          "http://example.com",
			Method:       http.MethodPost,
			Headers:      []entitiesWebhook.Headers{},
			RepositoryID: analysis.RepositoryID,
		}
		mockRead := &relational.MockRead{}
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(response.NewResponse(0, nil, webhookData))
		mockRequest := &request.Mock{}
		mockRequest.On("Request").Return(&http.Request{}, nil)
		mockClient := &client.Mock{}
		mockClient.On("DoRequest").Return(httpResponse.NewHTTPResponse(&http.Response{
			StatusCode: 400,
		}), nil)
		c := &Controller{
			databaseRead:      mockRead,
			webhookRepository: webhook.NewWebhookRepository(mockRead, nil),
			httpRequest:       mockRequest,
			httpClient:        mockClient,
		}
		err := c.DispatchRequest(analysis)
		assert.Equal(t, EnumErrors.ErrDoHTTPClientSide, err)
	})
	t.Run("Should return error because request return err service side", func(t *testing.T) {
		analysis := test.CreateAnalysisMock()
		webhookData := &entitiesWebhook.Webhook{
			WebhookID:    uuid.New(),
			URL:          "http://example.com",
			Method:       http.MethodPost,
			Headers:      []entitiesWebhook.Headers{},
			RepositoryID: analysis.RepositoryID,
		}
		mockRead := &relational.MockRead{}
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(response.NewResponse(0, nil, webhookData))
		mockRequest := &request.Mock{}
		mockRequest.On("Request").Return(&http.Request{}, nil)
		mockClient := &client.Mock{}
		mockClient.On("DoRequest").Return(httpResponse.NewHTTPResponse(&http.Response{
			StatusCode: 500,
		}), nil)
		c := &Controller{
			databaseRead:      mockRead,
			webhookRepository: webhook.NewWebhookRepository(mockRead, nil),
			httpRequest:       mockRequest,
			httpClient:        mockClient,
		}
		err := c.DispatchRequest(analysis)
		assert.Equal(t, EnumErrors.ErrDoHTTPServiceSide, err)
	})
	t.Run("Should dispatch request without error", func(t *testing.T) {
		analysis := test.CreateAnalysisMock()
		webhookData := &entitiesWebhook.Webhook{
			WebhookID: uuid.New(),
			URL:       "http://example.com",
			Method:    http.MethodPost,
			Headers: []entitiesWebhook.Headers{
				{
					Key:   "Authorization",
					Value: "Bearer Token",
				},
			},
			RepositoryID: analysis.RepositoryID,
		}
		mockRead := &relational.MockRead{}
		mockRead.On("SetFilter").Return(conn)
		mockRead.On("Find").Return(response.NewResponse(0, nil, webhookData))
		mockRequest := &request.Mock{}
		mockRequest.On("Request").Return(&http.Request{}, nil)
		mockClient := &client.Mock{}
		mockClient.On("DoRequest").Return(httpResponse.NewHTTPResponse(&http.Response{}), nil)
		c := &Controller{
			databaseRead:      mockRead,
			webhookRepository: webhook.NewWebhookRepository(mockRead, nil),
			httpRequest:       mockRequest,
			httpClient:        mockClient,
		}
		err := c.DispatchRequest(analysis)
		assert.NoError(t, err)
	})
}
