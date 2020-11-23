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

package webhook

import (
	"encoding/json"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/webhook"
	"io"
)

type IWebhook interface {
	NewWebhookFromReadCloser(body io.ReadCloser) (*webhook.Webhook, error)
}

type Webhook struct {
}

func NewWebhookUseCases() IWebhook {
	return &Webhook{}
}

func (w *Webhook) NewWebhookFromReadCloser(body io.ReadCloser) (webhookData *webhook.Webhook, err error) {
	err = json.NewDecoder(body).Decode(&webhookData)
	_ = body.Close()
	if err != nil {
		return nil, err
	}

	return webhookData, webhookData.Validate()
}
