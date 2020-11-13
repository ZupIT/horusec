package webhook

import (
	"errors"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	"github.com/ZupIT/horusec/development-kit/pkg/services/broker/packet"
	usecasesAnalysis "github.com/ZupIT/horusec/development-kit/pkg/usecases/analysis"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/test"
	"github.com/ZupIT/horusec/horusec-webhook/internal/controllers/webhook"
	"github.com/google/uuid"
	"github.com/streadway/amqp"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewConsumer(t *testing.T) {
	t.Run("Should not return empty when call NewConsumer", func(t *testing.T) {
		assert.NotEmpty(t, NewConsumer(&relational.MockRead{}))
	})
}

func TestConsumer_DispatchRequest(t *testing.T) {
	t.Run("Should return error because repositoryID and companyID is required in analysis object", func(t *testing.T) {
		controllerMock := &webhook.Mock{}
		consumer := Consumer{
			controller: controllerMock,
			usecase:    usecasesAnalysis.NewAnalysisUseCases(),
		}

		analysis := &horusec.Analysis{}
		brokerPacket := packet.NewPacket(&amqp.Delivery{Body: analysis.ToBytes()})
		consumer.DispatchRequest(brokerPacket)
		controllerMock.AssertNotCalled(t, "DispatchRequest")
	})
	t.Run("Should return error because companyID is required in analysis object", func(t *testing.T) {
		controllerMock := &webhook.Mock{}
		consumer := Consumer{
			controller: controllerMock,
			usecase:    usecasesAnalysis.NewAnalysisUseCases(),
		}

		analysis := &horusec.Analysis{
			RepositoryID: uuid.New(),
		}
		brokerPacket := packet.NewPacket(&amqp.Delivery{Body: analysis.ToBytes()})
		consumer.DispatchRequest(brokerPacket)
		controllerMock.AssertNotCalled(t, "DispatchRequest")
	})
	t.Run("Should dispatch with success request", func(t *testing.T) {
		controllerMock := &webhook.Mock{}
		controllerMock.On("DispatchRequest").Return(nil)
		consumer := Consumer{
			controller: controllerMock,
			usecase:    usecasesAnalysis.NewAnalysisUseCases(),
		}

		analysis := test.CreateAnalysisMock()
		brokerPacket := packet.NewPacket(&amqp.Delivery{Body: analysis.ToBytes()})
		consumer.DispatchRequest(brokerPacket)
		controllerMock.AssertCalled(t, "DispatchRequest")
	})
	t.Run("Should dispatch with error request", func(t *testing.T) {
		controllerMock := &webhook.Mock{}
		controllerMock.On("DispatchRequest").Return(errors.New("unexpected error"))
		consumer := Consumer{
			controller: controllerMock,
			usecase:    usecasesAnalysis.NewAnalysisUseCases(),
		}

		analysis := test.CreateAnalysisMock()
		brokerPacket := packet.NewPacket(&amqp.Delivery{Body: analysis.ToBytes()})
		consumer.DispatchRequest(brokerPacket)
		controllerMock.AssertCalled(t, "DispatchRequest")
	})
}
