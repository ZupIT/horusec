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
	"bytes"
	"html/template"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/messages"
	messagesEnum "github.com/ZupIT/horusec/development-kit/pkg/enums/messages"
	emailTemplates "github.com/ZupIT/horusec/horusec-messages/internal/controllers/email/templates"
	mailerLib "github.com/ZupIT/horusec/horusec-messages/internal/pkg/mailer"
	"gopkg.in/gomail.v2"
)

type Interface interface {
	SendEmail(*messages.EmailMessage) error
}

type Controller struct {
	mailer mailerLib.IMailer
	tpl    *template.Template
}

func NewController(mailer mailerLib.IMailer) Interface {
	tpl := template.Must(template.New(messagesEnum.EmailConfirmation).Parse(emailTemplates.EmailConfirmationTpl))
	tpl = template.Must(tpl.New(messagesEnum.ResetPassword).Parse(emailTemplates.ResetPasswordTpl))
	tpl = template.Must(tpl.New(messagesEnum.OrganizationInvite).Parse(emailTemplates.OrganizationInviteTpl))

	return &Controller{
		mailer: mailer,
		tpl:    tpl,
	}
}

func (c *Controller) SendEmail(emailMessage *messages.EmailMessage) error {
	body := new(bytes.Buffer)

	err := c.tpl.ExecuteTemplate(body, emailMessage.TemplateName, emailMessage.Data)
	if err != nil {
		return err
	}

	msg := c.createMessage()

	msg.SetHeader("Subject", emailMessage.Subject)
	msg.SetHeader("To", emailMessage.To)
	msg.SetBody("text/html", body.String())

	return c.mailer.SendEmail(msg)
}

func (c *Controller) createMessage() *gomail.Message {
	m := gomail.NewMessage()
	m.SetHeader("From", c.mailer.GetFromHeader())

	return m
}
