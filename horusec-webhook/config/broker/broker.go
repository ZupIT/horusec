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
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/enums/queues"
	brokerLib "github.com/ZupIT/horusec/development-kit/pkg/services/broker"
	"github.com/ZupIT/horusec/development-kit/pkg/services/broker/config"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/ZupIT/horusec/horusec-webhook/internal/events/webhook"
)

func SetUp(databaseRead relational.InterfaceRead) brokerLib.IBroker {
	broker, err := brokerLib.NewBroker(config.NewBrokerConfig())
	if err != nil {
		logger.LogPanic(errors.FailedConnectBroker, err)
	}

	setUpConsumers(broker, databaseRead)
	return broker
}

func setUpConsumers(broker brokerLib.IBroker, databaseRead relational.InterfaceRead) {
	consumer := webhook.NewConsumer(databaseRead)
	go broker.Consume(queues.HorusecWebhookDispatch.ToString(), "", "", consumer.DispatchRequest)
}
