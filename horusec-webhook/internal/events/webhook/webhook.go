package webhook

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	brokerPacket "github.com/ZupIT/horusec/development-kit/pkg/services/broker/packet"
	usecasesAnalysis "github.com/ZupIT/horusec/development-kit/pkg/usecases/analysis"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-webhook/internal/controllers/webhook"
)

type Consumer struct {
	controller webhook.Interface
	usecase    usecasesAnalysis.Interface
}

func NewConsumer(databaseRead relational.InterfaceRead) *Consumer {
	return &Consumer{
		controller: webhook.NewWebhookController(databaseRead),
		usecase:    usecasesAnalysis.NewAnalysisUseCases(),
	}
}

func (c *Consumer) DispatchRequest(packet brokerPacket.IPacket) {
	analysis, err := c.usecase.DecodeAnalysisFromBytes(packet.GetBody())
	if err != nil {
		logger.LogError("Error when decode packet to analysis", err)
		_ = packet.Ack()
		return
	}
	if err := c.controller.DispatchRequest(analysis); err != nil {
		logger.LogError("Error when dispatch request", err)
	} else {
		logger.LogInfo("Webhook Dispatch request with success")
	}
	_ = packet.Ack()
}
