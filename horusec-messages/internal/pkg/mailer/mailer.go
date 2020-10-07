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
	"crypto/tls"

	mailerConfig "github.com/ZupIT/horusec/horusec-messages/internal/pkg/mailer/config"
	"gopkg.in/gomail.v2"
)

type IMailer interface {
	SendEmail(msg *gomail.Message) error
	Noop() error
	IsAvailable() bool
	GetFromHeader() string
}

type Mailer struct {
	config mailerConfig.IMailerConfig
	dialer *gomail.Dialer
}

func NewMailer(config mailerConfig.IMailerConfig) (IMailer, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	mailer := &Mailer{config: config}
	mailer.dialer = gomail.NewDialer(config.GetHost(), config.GetPort(), config.GetUsername(), config.GetPassword())
	mailer.dialer.TLSConfig = &tls.Config{InsecureSkipVerify: true} //nolint is necessary to send without use tls check

	return mailer, nil
}

func (m *Mailer) SendEmail(msg *gomail.Message) error {
	return m.dialer.DialAndSend(msg)
}

func (m *Mailer) Noop() error {
	_, err := m.dialer.Dial()

	return err
}

func (m *Mailer) IsAvailable() bool {
	err := m.Noop()
	return err == nil
}

func (m *Mailer) GetFromHeader() string {
	return m.config.GetFrom()
}
