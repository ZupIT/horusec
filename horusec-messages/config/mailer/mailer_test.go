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
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestSetUp(t *testing.T) {
	t.Run("Should configure mailer and not return panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			_ = os.Setenv("HORUSEC_SMTP_ADDRESS", "smtp.mailtrap.io")
			_ = os.Setenv("HORUSEC_SMTP_USERNAME", "-")
			_ = os.Setenv("HORUSEC_SMTP_PASSWORD", "-")
			_ = os.Setenv("HORUSEC_SMTP_HOST", "smtp.mailtrap.io")
			_ = os.Setenv("HORUSEC_SMTP_PORT", "2525")
			_ = os.Setenv("HORUSEC_EMAIL_FROM", "horusec@zup.com.br")
			SetUp()
		})
	})
	t.Run("Should configure mailer and return panic", func(t *testing.T) {
		assert.Panics(t, func() {
			_ = os.Setenv("HORUSEC_SMTP_ADDRESS", "")
			_ = os.Setenv("HORUSEC_SMTP_USERNAME", "")
			_ = os.Setenv("HORUSEC_SMTP_PASSWORD", "")
			_ = os.Setenv("HORUSEC_SMTP_HOST", "")
			_ = os.Setenv("HORUSEC_SMTP_PORT", "")
			_ = os.Setenv("HORUSEC_EMAIL_FROM", "")
			SetUp()
		})
	})
}