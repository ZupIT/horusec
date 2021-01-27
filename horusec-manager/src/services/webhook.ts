/**
 * Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import http from 'config/axios/default';
import { WebhookHeader } from 'helpers/interfaces/Webhook';
import { SERVICE_ACCOUNT } from '../config/endpoints';

const getAll = (companyID: string) => {
  return http.get(`${SERVICE_ACCOUNT}/account/webhook/${companyID}`);
};

const create = (
  companyID: string,
  repositoryID: string,
  url: string,
  method: string,
  headers: WebhookHeader[],
  description: string
) => {
  return http.post(
    `${SERVICE_ACCOUNT}/account/webhook/${companyID}/${repositoryID}`,
    {
      url,
      method,
      headers,
      description,
    }
  );
};

const update = (
  companyID: string,
  repositoryID: string,
  webhookID: string,
  url: string,
  method: string,
  headers: WebhookHeader[],
  description: string
) => {
  return http.put(
    `${SERVICE_ACCOUNT}/account/webhook/${companyID}/${repositoryID}/${webhookID}`,
    {
      url,
      method,
      headers,
      description,
    }
  );
};

const remove = (companyID: string, repositoryID: string, webhookID: string) => {
  return http.delete(
    `${SERVICE_ACCOUNT}/account/webhook/${companyID}/${repositoryID}/${webhookID}`
  );
};

export default {
  getAll,
  remove,
  create,
  update,
};
