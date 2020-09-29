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

package email

import (
	"encoding/json"

	messagesEntities "github.com/ZupIT/horusec/development-kit/pkg/entities/messages"
	enumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	brokerPacket "github.com/ZupIT/horusec/development-kit/pkg/services/broker/packet"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-messages/internal/controllers/email"
	mailerLib "github.com/ZupIT/horusec/horusec-messages/internal/pkg/mailer"
)

type Consumer struct {
	controller email.Interface
}

func NewConsumer(mailer mailerLib.IMailer) *Consumer {
	return &Consumer{controller: email.NewController(mailer)}
}

func (c *Consumer) SendEmail(packet brokerPacket.IPacket) {
	var emailData *messagesEntities.EmailMessage

	if err := json.Unmarshal(packet.GetBody(), &emailData); err != nil {
		logger.LogError(enumErrors.ErrParsePacketToEmailConfirmation, err)
		_ = packet.Ack()
		return
	}

	if err := c.controller.SendEmail(emailData); err != nil {
		logger.LogError(enumErrors.ErrSendingEmail, err)
	} else {
		logger.LogInfo("E-mail sent with success")
	}

	_ = packet.Ack()
}
