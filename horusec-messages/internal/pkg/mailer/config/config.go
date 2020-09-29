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
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type IMailerConfig interface {
	Validate() error
	SetAddress(address string)
	GetAddress() string
	SetUsername(username string)
	GetUsername() string
	SetPassword(password string)
	GetPassword() string
	SetHost(host string)
	GetHost() string
	SetPort(port int)
	GetPort() int
	SetFrom(from string)
	GetFrom() string
}

type MailerConfig struct {
	address  string
	username string
	password string
	host     string
	port     int
	from     string
}

func NewMailerConfig() IMailerConfig {
	config := &MailerConfig{}
	config.SetAddress(env.GetEnvOrDefault("HORUSEC_SMTP_ADDRESS", ""))
	config.SetUsername(env.GetEnvOrDefault("HORUSEC_SMTP_USERNAME", ""))
	config.SetPassword(env.GetEnvOrDefault("HORUSEC_SMTP_PASSWORD", ""))
	config.SetHost(env.GetEnvOrDefault("HORUSEC_SMTP_HOST", ""))
	config.SetPort(env.GetEnvOrDefaultInt("HORUSEC_SMTP_PORT", 25))
	config.SetFrom(env.GetEnvOrDefault("HORUSEC_EMAIL_FROM", "horusec@zup.com.br"))

	return config
}

func (c *MailerConfig) Validate() error {
	validations := []*validation.FieldRules{
		validation.Field(&c.address, validation.Required),
		validation.Field(&c.host, validation.Required),
		validation.Field(&c.port, validation.Required),
		validation.Field(&c.username, validation.Required),
		validation.Field(&c.password, validation.Required),
		validation.Field(&c.from, validation.Required),
	}

	return validation.ValidateStruct(c, validations...)
}

func (c *MailerConfig) SetAddress(address string) {
	c.address = address
}

func (c *MailerConfig) GetAddress() string {
	return c.address
}

func (c *MailerConfig) SetHost(host string) {
	c.host = host
}

func (c *MailerConfig) GetHost() string {
	return c.host
}

func (c *MailerConfig) SetUsername(username string) {
	c.username = username
}

func (c *MailerConfig) GetUsername() string {
	return c.username
}

func (c *MailerConfig) SetPassword(password string) {
	c.password = password
}

func (c *MailerConfig) GetPassword() string {
	return c.password
}

func (c *MailerConfig) SetPort(port int) {
	c.port = port
}

func (c *MailerConfig) GetPort() int {
	return c.port
}

func (c *MailerConfig) SetFrom(from string) {
	c.from = from
}

func (c *MailerConfig) GetFrom() string {
	return c.from
}
