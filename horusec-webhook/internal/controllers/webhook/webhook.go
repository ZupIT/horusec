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
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational/repository/webhook"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	entitiesWebhook "github.com/ZupIT/horusec/development-kit/pkg/entities/webhook"
	EnumErrors "github.com/ZupIT/horusec/development-kit/pkg/enums/errors"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/env"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/client"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/http-request/request"
)

type Interface interface {
	DispatchRequest(analysis *horusec.Analysis) error
}

type Controller struct {
	databaseRead      relational.InterfaceRead
	webhookRepository webhook.IWebhook
	httpRequest       request.Interface
	httpClient        client.Interface
}

func NewWebhookController(databaseRead relational.InterfaceRead) Interface {
	return &Controller{
		databaseRead:      databaseRead,
		webhookRepository: webhook.NewWebhookRepository(databaseRead, nil),
		httpRequest:       request.NewHTTPRequest(),
		httpClient:        client.NewHTTPClient(env.GetEnvOrDefaultInt("HORUSEC_HTTP_TIMEOUT", 60)),
	}
}

func (c *Controller) DispatchRequest(analysis *horusec.Analysis) error {
	webhookFound, err := c.webhookRepository.GetByRepositoryID(analysis.RepositoryID)
	if err != nil {
		if err == EnumErrors.ErrNotFoundRecords {
			return nil
		}
		return err
	}
	return c.sendHTTPRequest(webhookFound, analysis)
}

func (c *Controller) sendHTTPRequest(webhookFound *entitiesWebhook.Webhook, analysis *horusec.Analysis) error {
	req, err := c.httpRequest.Request(webhookFound.GetMethod(), webhookFound.URL, analysis, webhookFound.GetHeaders())
	if err != nil {
		return err
	}
	res, err := c.httpClient.DoRequest(req, nil)
	if err != nil {
		return err
	}
	defer res.CloseBody()
	return res.ErrorByStatusCode()
}
