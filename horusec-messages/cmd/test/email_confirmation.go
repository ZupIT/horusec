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

package main

import (
	"github.com/ZupIT/horusec/development-kit/pkg/entities/messages"
	mailerConfig "github.com/ZupIT/horusec/horusec-messages/config/mailer"
	"github.com/ZupIT/horusec/horusec-messages/internal/controllers/email"
)

func main() {
	mailer := mailerConfig.SetUp()
	controller := email.NewController(mailer)
	err := controller.SendEmail(&messages.EmailMessage{
		To:           "example@gmail.com",
		Subject:      "[Horusec][Test] Email confirmation",
		TemplateName: "email-confirmation",
		Data:         map[string]interface{}{"Username": "test", "URL": "http://localhost:8003"},
	})

	if err != nil {
		print(err)
	}
}
