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

package queues

import "strings"

type Queue string

const (
	HorusecEmail           Queue = "horusec-email"
	HorusecWebhookDispatch Queue = "horusec-webhook-dispatch"
	UNKNOWN                Queue = "unknown"
)

func Values() []Queue {
	return []Queue{
		HorusecEmail,
		HorusecWebhookDispatch,
	}
}

func IsValid(queue Queue) bool {
	for _, value := range Values() {
		if queue == value {
			return true
		}
	}

	return false
}

func IsInvalid(value Queue) bool {
	return !IsValid(value)
}

func IsEqual(value string, queue Queue) bool {
	return strings.EqualFold(string(queue), value)
}

func ValueOf(value string) Queue {
	for _, queue := range Values() {
		if IsEqual(value, queue) {
			return queue
		}
	}

	return UNKNOWN
}

func (q Queue) ToString() string {
	return string(q)
}
