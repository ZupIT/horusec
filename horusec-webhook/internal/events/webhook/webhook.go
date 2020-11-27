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
