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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewMailerConfig(t *testing.T) {
	t.Run("should successfully create mailer config", func(t *testing.T) {
		config := NewMailerConfig()
		assert.NotNil(t, config)
	})
}

func TestGetAddress(t *testing.T) {
	t.Run("should return a string", func(t *testing.T) {
		address := NewMailerConfig().GetFrom()
		assert.NotNil(t, address)
	})
}

func TestGetUsername(t *testing.T) {
	t.Run("should return a string", func(t *testing.T) {
		username := NewMailerConfig().GetUsername()
		assert.NotNil(t, username)
	})
}

func TestGetPassword(t *testing.T) {
	t.Run("should return a string", func(t *testing.T) {
		password := NewMailerConfig().GetPassword()
		assert.NotNil(t, password)
	})
}

func TestGetHost(t *testing.T) {
	t.Run("should return a string", func(t *testing.T) {
		host := NewMailerConfig().GetHost()
		assert.NotNil(t, host)
	})
}

func TestGetPort(t *testing.T) {
	t.Run("should return a string", func(t *testing.T) {
		port := NewMailerConfig().GetPort()
		assert.NotNil(t, port)
	})
}

func TestGetFrom(t *testing.T) {
	t.Run("should return a string", func(t *testing.T) {
		from := NewMailerConfig().GetFrom()
		assert.NotNil(t, from)
	})
}

func TestSetUsername(t *testing.T) {
	t.Run("should set a string", func(t *testing.T) {
		config := NewMailerConfig()
		config.SetUsername("test-username")
		assert.Equal(t, config.GetUsername(), "test-username")
	})
}

func TestSetPassword(t *testing.T) {
	t.Run("should set a string", func(t *testing.T) {
		config := NewMailerConfig()
		config.SetPassword("test-password")
		assert.Equal(t, config.GetPassword(), "test-password")
	})
}

func TestSetHost(t *testing.T) {
	t.Run("should set a string", func(t *testing.T) {
		config := NewMailerConfig()
		config.SetHost("test-host")
		assert.Equal(t, config.GetHost(), "test-host")
	})
}

func TestSetPort(t *testing.T) {
	t.Run("should set a string", func(t *testing.T) {
		config := NewMailerConfig()
		config.SetPort(10)
		assert.Equal(t, config.GetPort(), 10)
	})
}

func TestSetFrom(t *testing.T) {
	t.Run("should set a string", func(t *testing.T) {
		config := NewMailerConfig()
		config.SetFrom("test-from")
		assert.Equal(t, config.GetFrom(), "test-from")
	})
}

func TestValidate(t *testing.T) {
	t.Run("should throw an error when the required environment variables is not setted", func(t *testing.T) {
		os.Unsetenv("HORUSEC_SMTP_ADDRESS")
		os.Unsetenv("HORUSEC_SMTP_USERNAME")
		os.Unsetenv("HORUSEC_SMTP_PASSWORD")
		os.Unsetenv("HORUSEC_SMTP_HOST")
		os.Unsetenv("HORUSEC_SMTP_PORT")
		os.Unsetenv("HORUSEC_EMAIL_FROM")
		config := NewMailerConfig()
		err := config.Validate()

		assert.Error(t, err, "address: cannot be blank; host: cannot be blank; password: cannot be blank; username: cannot be blank.")
	})

	t.Run("should return nil when the required environment variables is correctly setted", func(t *testing.T) {
		os.Setenv("HORUSEC_SMTP_ADDRESS", "test")
		os.Setenv("HORUSEC_SMTP_USERNAME", "test")
		os.Setenv("HORUSEC_SMTP_PASSWORD", "test")
		os.Setenv("HORUSEC_SMTP_HOST", "test")
		os.Setenv("HORUSEC_SMTP_PORT", "test")
		os.Setenv("HORUSEC_EMAIL_FROM", "test")
		config := NewMailerConfig()
		err := config.Validate()

		assert.NoError(t, err)
	})
}
