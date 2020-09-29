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
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	mailerLib "github.com/ZupIT/horusec/horusec-messages/internal/pkg/mailer"
	mailerConfig "github.com/ZupIT/horusec/horusec-messages/internal/pkg/mailer/config"
)

func SetUp() mailerLib.IMailer {
	config := mailerConfig.NewMailerConfig()
	mailer, err := mailerLib.NewMailer(config)
	if err != nil {
		logger.LogPanic(errors.FailedConnectMailer, err)
	}

	return mailer
}
