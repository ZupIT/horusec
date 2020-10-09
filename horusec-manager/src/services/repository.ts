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

import renewHTTP from 'services/axios/forceRenewToken';
import defaultHTTP from 'services/axios/default';

import { SERVICE_COMPANY, SERVICE_API, SERVICE_REPOSITORY } from './enpoints';

const getAll = (companyId: string) => {
  return renewHTTP.get(`${SERVICE_COMPANY}/${companyId}/repositories`);
};

const create = (companyId: string, name: string, description: string) => {
  return renewHTTP.post(`${SERVICE_COMPANY}/${companyId}/repositories`, {
    name,
    description,
  });
};

const update = (
  companyId: string,
  repositoryId: string,
  name: string,
  description: string
) => {
  return renewHTTP.patch(
    `${SERVICE_COMPANY}/${companyId}/repositories/${repositoryId}`,
    { name, description }
  );
};

const remove = (companyId: string, repositoryId: string) => {
  return renewHTTP.delete(
    `${SERVICE_COMPANY}/${companyId}/repositories/${repositoryId}`
  );
};

const getAllTokens = (companyId: string, repositoryId: string) => {
  return renewHTTP.get(
    `${SERVICE_API}/${companyId}/repositories/${repositoryId}/tokens`
  );
};

const createToken = (
  companyId: string,
  repositoryId: string,
  description: string
) => {
  return renewHTTP.post(
    `${SERVICE_API}/${companyId}/repositories/${repositoryId}/tokens`,
    {
      description,
    }
  );
};

const removeToken = (
  companyId: string,
  repositoryId: string,
  tokenId: string
) => {
  return renewHTTP.delete(
    `${SERVICE_API}/${companyId}/repositories/${repositoryId}/tokens/${tokenId}`
  );
};

const getUsersInRepository = (companyId: string, repositoryId: string) => {
  return renewHTTP.get(
    `${SERVICE_COMPANY}/${companyId}/repositories/${repositoryId}/roles`
  );
};

const includeUser = (
  companyId: string,
  repositoryId: string,
  email: string,
  role: string
) => {
  return renewHTTP.post(
    `${SERVICE_COMPANY}/${companyId}/repositories/${repositoryId}/roles`,
    {
      email,
      role,
    }
  );
};

const removeUser = (
  companyId: string,
  repositoryId: string,
  accountId: string
) => {
  return renewHTTP.delete(
    `${SERVICE_COMPANY}/${companyId}/repositories/${repositoryId}/roles/${accountId}`
  );
};

const updateUserRole = (
  companyId: string,
  repositoryId: string,
  accountId: string,
  role: string
) => {
  return renewHTTP.patch(
    `${SERVICE_COMPANY}/${companyId}/repositories/${repositoryId}/roles/${accountId}`,
    {
      role,
    }
  );
};

const getAllVulnerabilities = (
  repositoryId: string,
  page: number,
  size: number,
  vulnHash?: string,
  vulnType?: string
) => {
  return defaultHTTP.get(`${SERVICE_REPOSITORY}/${repositoryId}/management`, {
    params: { page, size, vulnType, vulnHash },
  });
};

const updateVulnerabilityType = (
  repositoryId: string,
  vulnerabilityId: string,
  type: string
) => {
  return defaultHTTP.put(
    `${SERVICE_REPOSITORY}/${repositoryId}/management/${vulnerabilityId}/type`,
    {
      type,
    }
  );
};

export default {
  getAll,
  create,
  update,
  remove,
  getAllTokens,
  createToken,
  removeToken,
  getUsersInRepository,
  includeUser,
  removeUser,
  updateUserRole,
  getAllVulnerabilities,
  updateVulnerabilityType,
};
