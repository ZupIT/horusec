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

package errors

const (
	FailedConnectBroker           = "{ERROR_BROKER} failed to connect"
	FailedCreateChannelPublish    = "{ERROR_BROKER} failed to create channel while publishing"
	FailedDeclareExchangePublish  = "{ERROR_BROKER} failed to declare exchange while publishing"
	FailedCreateChannelConsume    = "{ERROR_BROKER} failed to create channel in consume"
	FailedCreateQueueConsume      = "{ERROR_BROKER} error declaring queue in consume"
	FailedConsumeHandlingDelivery = "{ERROR_BROKER} consume error while handling deliveries"
	FailedSetConsumerPrefetch     = "{ERROR_BROKER} failed to set consumer prefetch"
	FailedToDeclareExchangeQueue  = "{ERROR_BROKER} failed to declare exchange while declaring queue"
	FailedBindQueueConsume        = "{ERROR_BROKER} failed to queue bind in consume"
)
