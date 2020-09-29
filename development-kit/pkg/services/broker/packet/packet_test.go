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

package packet

import (
	"github.com/streadway/amqp"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewPacket(t *testing.T) {
	t.Run("should create a new packet", func(t *testing.T) {
		packet := NewPacket(&amqp.Delivery{})
		assert.NotNil(t, packet)
	})
}

func TestAck(t *testing.T) {
	t.Run("return error when ack a empty packet", func(t *testing.T) {
		packet := NewPacket(&amqp.Delivery{})
		assert.Error(t, packet.Ack())
	})
}

func TestNack(t *testing.T) {
	t.Run("return error when nack a empty packet", func(t *testing.T) {
		packet := NewPacket(&amqp.Delivery{})
		assert.Error(t, packet.Nack())
	})
}

func TestGetBody(t *testing.T) {
	t.Run("should return packet body in bytes", func(t *testing.T) {
		packet := NewPacket(&amqp.Delivery{Body: []byte("test-body")})
		assert.Equal(t, "test-body", string(packet.GetBody()))
	})
}

func TestSetBody(t *testing.T) {
	t.Run("should success set packet body", func(t *testing.T) {
		packet := NewPacket(&amqp.Delivery{})

		assert.NotPanics(t, func() {
			packet.SetBody([]byte("test"))
		})
	})
}
