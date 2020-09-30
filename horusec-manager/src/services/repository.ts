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

import http from 'services/axios/forceRenewToken';
import { SERVICE_COMPANY, SERVICE_API } from './enpoints';

const getAll = (companyId: string) => {
  return http.get(`${SERVICE_COMPANY}/${companyId}/repositories`);
};

const create = (companyId: string, name: string, description: string) => {
  return http.post(`${SERVICE_COMPANY}/${companyId}/repositories`, {
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
  return http.patch(
    `${SERVICE_COMPANY}/${companyId}/repositories/${repositoryId}`,
    { name, description }
  );
};

const remove = (companyId: string, repositoryId: string) => {
  return http.delete(
    `${SERVICE_COMPANY}/${companyId}/repositories/${repositoryId}`
  );
};

const getAllTokens = (companyId: string, repositoryId: string) => {
  return http.get(
    `${SERVICE_API}/${companyId}/repositories/${repositoryId}/tokens`
  );
};

const createToken = (
  companyId: string,
  repositoryId: string,
  description: string
) => {
  return http.post(
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
  return http.delete(
    `${SERVICE_API}/${companyId}/repositories/${repositoryId}/tokens/${tokenId}`
  );
};

const getUsersInRepository = (companyId: string, repositoryId: string) => {
  return http.get(
    `${SERVICE_COMPANY}/${companyId}/repositories/${repositoryId}/roles`
  );
};

const includeUser = (
  companyId: string,
  repositoryId: string,
  email: string,
  role: string
) => {
  return http.post(
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
  return http.delete(
    `${SERVICE_COMPANY}/${companyId}/repositories/${repositoryId}/roles/${accountId}`
  );
};

const updateUserRole = (
  companyId: string,
  repositoryId: string,
  accountId: string,
  role: string
) => {
  return http.patch(
    `${SERVICE_COMPANY}/${companyId}/repositories/${repositoryId}/roles/${accountId}`,
    {
      role,
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
};
