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

package mailer

import (
	config2 "github.com/ZupIT/horusec/horusec-messages/internal/pkg/mailer/config"
	"github.com/stretchr/testify/assert"
	"gopkg.in/gomail.v2"
	"os"
	"testing"
)

func TestMock(t *testing.T) {
	mock := &Mock{}
	mock.On("IsAvailable").Return(true)
	mock.On("Noop").Return(nil)
	mock.On("SendEmail").Return(nil)
	mock.On("GetFromHeader").Return("")
	_ = mock.IsAvailable()
	_ = mock.Noop()
	_ = mock.SendEmail(&gomail.Message{})
	_ = mock.GetFromHeader()
}

func TestMailer_IsAvailable(t *testing.T) {
	_ = os.Setenv("HORUSEC_SMTP_ADDRESS", "smtp.mailtrap.io")
	_ = os.Setenv("HORUSEC_SMTP_USERNAME", "-")
	_ = os.Setenv("HORUSEC_SMTP_PASSWORD", "-")
	_ = os.Setenv("HORUSEC_SMTP_HOST", "smtp.mailtrap.io")
	_ = os.Setenv("HORUSEC_SMTP_PORT", "2525")
	_ = os.Setenv("HORUSEC_EMAIL_FROM", "horusec@zup.com.br")
	config := config2.NewMailerConfig()
	t.Run("Should return GetFromHeader empty", func(t *testing.T) {
		m, err := NewMailer(config)
		assert.NoError(t, err)
		assert.NotEmpty(t, m)
		assert.False(t, m.IsAvailable())
	})
}

func TestMailer_Noop(t *testing.T) {
	_ = os.Setenv("HORUSEC_SMTP_ADDRESS", "smtp.mailtrap.io")
	_ = os.Setenv("HORUSEC_SMTP_USERNAME", "-")
	_ = os.Setenv("HORUSEC_SMTP_PASSWORD", "-")
	_ = os.Setenv("HORUSEC_SMTP_HOST", "smtp.mailtrap.io")
	_ = os.Setenv("HORUSEC_SMTP_PORT", "2525")
	_ = os.Setenv("HORUSEC_EMAIL_FROM", "horusec@zup.com.br")
	config := config2.NewMailerConfig()
	t.Run("Should return Noop error", func(t *testing.T) {
		m, err := NewMailer(config)
		assert.NoError(t, err)
		assert.NotEmpty(t, m)
		assert.Error(t, m.Noop())
	})
}

func TestMock_SendEmail(t *testing.T) {
	_ = os.Setenv("HORUSEC_SMTP_ADDRESS", "smtp.mailtrap.io")
	_ = os.Setenv("HORUSEC_SMTP_USERNAME", "-")
	_ = os.Setenv("HORUSEC_SMTP_PASSWORD", "-")
	_ = os.Setenv("HORUSEC_SMTP_HOST", "smtp.mailtrap.io")
	_ = os.Setenv("HORUSEC_SMTP_PORT", "2525")
	_ = os.Setenv("HORUSEC_EMAIL_FROM", "horusec@zup.com.br")
	config := config2.NewMailerConfig()
	t.Run("Should return SendEmail error", func(t *testing.T) {
		m, err := NewMailer(config)
		assert.NoError(t, err)
		assert.NotEmpty(t, m)
		assert.Error(t, m.SendEmail(&gomail.Message{}))
	})
}

func TestMock_GetFromHeader(t *testing.T) {
	_ = os.Setenv("HORUSEC_SMTP_ADDRESS", "smtp.mailtrap.io")
	_ = os.Setenv("HORUSEC_SMTP_USERNAME", "-")
	_ = os.Setenv("HORUSEC_SMTP_PASSWORD", "-")
	_ = os.Setenv("HORUSEC_SMTP_HOST", "smtp.mailtrap.io")
	_ = os.Setenv("HORUSEC_SMTP_PORT", "2525")
	_ = os.Setenv("HORUSEC_EMAIL_FROM", "horusec@zup.com.br")
	config := config2.NewMailerConfig()
	t.Run("Should return header empty", func(t *testing.T) {
		m, err := NewMailer(config)
		assert.NoError(t, err)
		assert.NotEmpty(t, m)
		assert.Equal(t, "horusec@zup.com.br", m.GetFromHeader())
	})
}
