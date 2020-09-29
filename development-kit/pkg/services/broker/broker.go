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

package broker

import (
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	brokerConfig "github.com/ZupIT/horusec/development-kit/pkg/services/broker/config"
	brokerPacket "github.com/ZupIT/horusec/development-kit/pkg/services/broker/packet"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/streadway/amqp"
)

type IBroker interface {
	IsAvailable() bool
	Consume(queue, exchange, exchangeKind string, handler func(packet brokerPacket.IPacket))
	Publish(queue, exchange, exchangeKind string, body []byte) error
	Close() error
}

type Broker struct {
	connection *amqp.Connection
	channel    *amqp.Channel
	config     brokerConfig.IConfig
}

func NewBroker(config brokerConfig.IConfig) (IBroker, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	broker := &Broker{config: config}
	if err := broker.setUpConnection(); err != nil {
		return nil, err
	}

	return broker, broker.setUpChannel()
}

func (b *Broker) setUpConnection() (err error) {
	if b.connection == nil || b.connection == (&amqp.Connection{}) {
		b.connection, err = b.makeConnection()
	}

	if b.connection.IsClosed() {
		b.connection, err = b.makeConnection()
	}

	return err
}

func (b *Broker) makeConnection() (*amqp.Connection, error) {
	return amqp.Dial(b.config.GetConnectionString())
}

func (b *Broker) setUpChannel() (channelErr error) {
	if err := b.setUpConnection(); err != nil {
		return err
	}

	if b.channel == nil || b.channel == (&amqp.Channel{}) {
		b.channel, channelErr = b.connection.Channel()
	}

	if err := b.channel.Flow(true); err != nil {
		b.channel, channelErr = b.connection.Channel()
	}

	return channelErr
}

func (b *Broker) IsAvailable() bool {
	if err := b.setUpConnection(); err != nil {
		return false
	}

	if b.connection == nil || b.connection == (&amqp.Connection{}) {
		return false
	}

	return !b.connection.IsClosed()
}

func (b *Broker) Close() error {
	return b.connection.Close()
}

func (b *Broker) publish(queue string, data []byte, exchange string) error {
	packet := amqp.Publishing{
		ContentType: "text/plain",
		Body:        data,
	}

	return b.channel.Publish(exchange, queue, false, false, packet)
}

func (b *Broker) exchangeDeclare(exchange, exchangeKind string) error {
	if exchange == "" || exchangeKind == "" {
		return nil
	}

	return b.channel.ExchangeDeclare(exchange, exchangeKind, true, false, false,
		false, nil)
}

func (b *Broker) Publish(queue, exchange, exchangeKind string, body []byte) error {
	if err := b.setUpChannel(); err != nil {
		logger.LogError(errors.FailedCreateChannelPublish, err)
		return err
	}

	if err := b.exchangeDeclare(exchange, exchangeKind); err != nil {
		logger.LogError(errors.FailedDeclareExchangePublish, err)
		return err
	}

	return b.publish(queue, body, exchange)
}

func (b *Broker) Consume(queue, exchange, exchangeKing string, handler func(packet brokerPacket.IPacket)) {
	for {
		if err := b.setUpChannel(); err != nil {
			logger.LogPanic(errors.FailedCreateChannelConsume, err)
		}

		b.setConsumerPrefetch()
		b.declareQueueAndBind(queue, exchange, exchangeKing)
		b.handleDeliveries(queue, handler)
	}
}

func (b *Broker) declareQueueAndBind(queue, exchange, exchangeKing string) {
	if _, err := b.channel.QueueDeclare(queue, true, false, false,
		false, nil); err != nil {
		logger.LogPanic(errors.FailedCreateQueueConsume, err)
	}

	if exchange != "" && exchangeKing != "" {
		b.declareExchangeAndBind(queue, exchange, exchangeKing)
	}
}

func (b *Broker) handleDeliveries(queue string, handler func(packet brokerPacket.IPacket)) {
	deliveries, err := b.channel.Consume(queue, "", false, false, false,
		false, nil)
	if err != nil {
		logger.LogPanic(errors.FailedConsumeHandlingDelivery, err)
	}

	for delivery := range deliveries {
		message := delivery
		p := brokerPacket.NewPacket(&message)
		handler(p)
	}
}

func (b *Broker) setConsumerPrefetch() {
	if err := b.channel.Qos(1, 0, false); err != nil {
		logger.LogPanic(errors.FailedSetConsumerPrefetch, err)
	}
}

func (b *Broker) declareExchangeAndBind(queue, exchange, exchangeKing string) {
	if err := b.exchangeDeclare(exchange, exchangeKing); err != nil {
		logger.LogPanic(errors.FailedToDeclareExchangeQueue, err)
	}

	if err := b.channel.QueueBind(queue, "", exchange, false, nil); err != nil {
		logger.LogPanic(errors.FailedBindQueueConsume, err)
	}
}
