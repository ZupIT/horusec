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

package broker

import (
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	brokerLib "github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	"github.com/ZupIT/horusec/development-kit/pkg/services/broker/config"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
)

func SetUp() brokerLib.IBroker {
	broker, err := brokerLib.NewBroker(config.NewBrokerConfig())
	if err != nil {
		logger.LogPanic(errors.FailedConnectBroker, err)
	}

	setUpConsumers(broker)
	return broker
}

// nolint
func setUpConsumers(broker brokerLib.IBroker) {
	// consumer := email.NewConsumer()
	// go broker.Consume(queues.HorusecEmail.ToString(), "", "", consumer.SendEmail)
}
