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
	"errors"
	"testing"

	"github.com/streadway/amqp"

	messagesEntity "github.com/ZupIT/horusec/development-kit/pkg/entities/messages"
	"github.com/ZupIT/horusec/development-kit/pkg/services/broker/packet"
	"github.com/ZupIT/horusec/horusec-messages/internal/pkg/mailer"
	"github.com/stretchr/testify/assert"
)

func TestNewConsumer(t *testing.T) {
	t.Run("should successful create a new consumer", func(t *testing.T) {
		consumer := NewConsumer(&mailer.Mock{})

		assert.NotEmpty(t, consumer)
	})
}

func TestSendEmail(t *testing.T) {
	t.Run("should call controller send email", func(t *testing.T) {
		mailerMock := &mailer.Mock{}
		mailerMock.On("SendEmail").Return(nil)
		mailerMock.On("GetFromHeader").Return("")

		emailData := messagesEntity.EmailMessage{To: "test@horusec.com.br", TemplateName: "email-confirmation"}
		byteEmail, _ := json.Marshal(&emailData)

		brokerPacket := packet.NewPacket(&amqp.Delivery{Body: byteEmail})

		consumer := NewConsumer(mailerMock)
		consumer.SendEmail(brokerPacket)

		mailerMock.AssertCalled(t, "SendEmail")
	})
	t.Run("should controller return error when send email", func(t *testing.T) {
		mailerMock := &mailer.Mock{}
		mailerMock.On("SendEmail").Return(errors.New("unexpected error"))
		mailerMock.On("GetFromHeader").Return("")

		emailData := messagesEntity.EmailMessage{To: "test@horusec.com.br", TemplateName: "email-confirmation"}
		byteEmail, _ := json.Marshal(&emailData)

		brokerPacket := packet.NewPacket(&amqp.Delivery{Body: byteEmail})

		consumer := NewConsumer(mailerMock)
		consumer.SendEmail(brokerPacket)

		mailerMock.AssertCalled(t, "SendEmail")
	})

	t.Run("should not call controller send email if unmarshal fails", func(t *testing.T) {
		mailerMock := &mailer.Mock{}
		mailerMock.On("SendEmail").Return(nil)
		mailerMock.On("GetFromHeader").Return("")

		emailData := struct{ To bool }{To: true}
		byteEmail, _ := json.Marshal(&emailData)

		brokerPacket := packet.NewPacket(&amqp.Delivery{Body: byteEmail})

		consumer := NewConsumer(mailerMock)
		consumer.SendEmail(brokerPacket)

		mailerMock.AssertNotCalled(t, "SendEmail")
	})
}
