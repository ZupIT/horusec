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
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/messages"
	"github.com/ZupIT/horusec/horusec-messages/internal/pkg/mailer"
	"github.com/stretchr/testify/assert"
)

func TestNewController(t *testing.T) {
	t.Run("should successful creates a new controoler", func(t *testing.T) {
		mailerMock := &mailer.Mock{}
		controller := NewController(mailerMock)

		assert.NotEmpty(t, controller)
	})
}

func TestSendEmail(t *testing.T) {
	t.Run("should return an error when the template does not exist", func(t *testing.T) {
		mailerMock := &mailer.Mock{}
		mailerMock.On("SendEmail").Return(nil)
		mailerMock.On("GetFromHeader").Return("")
		controller := NewController(mailerMock)

		emailData := &messages.EmailMessage{
			To:           "test@horusec.com.br",
			TemplateName: "$_#@#)iwillneverexist9912",
		}

		assert.Error(t, controller.SendEmail(emailData), "test")
	})

	t.Run("shoul call mailer sendEmail with all templates", func(t *testing.T) {
		mailerMock := &mailer.Mock{}
		mailerMock.On("SendEmail").Return(nil)
		mailerMock.On("GetFromHeader").Return("")
		controller := NewController(mailerMock)

		emailConfirmation := &messages.EmailMessage{
			To:           "test@horusec.com.br",
			TemplateName: "email-confirmation",
		}

		resetPassword := &messages.EmailMessage{
			To:           "test@horusec.com.br",
			TemplateName: "email-confirmation",
		}

		organizationInvite := &messages.EmailMessage{
			To:           "test@horusec.com.br",
			TemplateName: "email-confirmation",
		}

		controller.SendEmail(emailConfirmation)
		controller.SendEmail(resetPassword)
		controller.SendEmail(organizationInvite)

		mailerMock.AssertNumberOfCalls(t, "SendEmail", 3)
	})
}
