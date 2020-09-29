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

package config

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewBrokerConfig(t *testing.T) {
	t.Run("should success create new broker start", func(t *testing.T) {
		config := NewBrokerConfig()
		assert.NotNil(t, config)
		assert.NotEmpty(t, config)
	})
}

func TestValidate(t *testing.T) {
	t.Run("should return no error when data is full filled correctly", func(t *testing.T) {
		config := NewBrokerConfig()

		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("should return error when host is empty", func(t *testing.T) {
		config := NewBrokerConfig()
		config.SetHost("")

		err := config.Validate()
		assert.Error(t, err)
	})

	t.Run("should return error when port is empty", func(t *testing.T) {
		config := NewBrokerConfig()
		config.SetPort("")

		err := config.Validate()
		assert.Error(t, err)
	})

	t.Run("should return error when username is empty", func(t *testing.T) {
		config := NewBrokerConfig()
		config.SetUsername("")

		err := config.Validate()
		assert.Error(t, err)
	})

	t.Run("should return error when password is empty", func(t *testing.T) {
		config := NewBrokerConfig()
		config.SetPassword("")

		err := config.Validate()
		assert.Error(t, err)
	})
}
func TestGetConnectionString(t *testing.T) {
	t.Run("should get broker connection string", func(t *testing.T) {
		config := NewBrokerConfig()

		assert.NotEmpty(t, config.GetConnectionString())
		assert.Equal(t, "amqp://guest:guest@127.0.0.1:5672", config.GetConnectionString())
	})
}

func TestGetAndSetUsername(t *testing.T) {
	t.Run("should success set and get broker username", func(t *testing.T) {
		config := NewBrokerConfig()
		config.SetUsername("test-username")

		assert.NotEmpty(t, config.GetUsername())
		assert.Equal(t, "test-username", config.GetUsername())
	})
}

func TestGetAndSetPassword(t *testing.T) {
	t.Run("should success set and get broker password", func(t *testing.T) {
		config := NewBrokerConfig()
		config.SetPassword("test-password")

		assert.NotEmpty(t, config.GetPassword())
		assert.Equal(t, "test-password", config.GetPassword())
	})
}

func TestGetAndSetPort(t *testing.T) {
	t.Run("should success set and get broker port", func(t *testing.T) {
		config := NewBrokerConfig()
		config.SetPort("test-port")

		assert.NotEmpty(t, config.GetPort())
		assert.Equal(t, "test-port", config.GetPort())
	})
}

func TestGetAndSetHost(t *testing.T) {
	t.Run("should success set and get broker host", func(t *testing.T) {
		config := NewBrokerConfig()
		config.SetHost("test-host")

		assert.NotEmpty(t, config.GetHost())
		assert.Equal(t, "test-host", config.GetHost())
	})
}
