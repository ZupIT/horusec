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

import http from 'services/axios/default';
import { SERVICE_COMPANY, SERVICE_API } from './enpoints';

const getAll = () => {
  return http.get(SERVICE_COMPANY);
};

const getOne = (companyId: string) => {
  return http.get(`${SERVICE_COMPANY}/${companyId}`);
};

const create = (name: string) => {
  return http.post(SERVICE_COMPANY, { name });
};

const update = (companyId: string, name: string) => {
  return http.patch(`${SERVICE_COMPANY}/${companyId}`, { name });
};

const remove = (companyId: string) => {
  return http.delete(`${SERVICE_COMPANY}/${companyId}`);
};

const getUsersInCompany = (companyId: string) => {
  return http.get(`${SERVICE_COMPANY}/${companyId}/roles`);
};

const createUserInCompany = (
  companyId: string,
  email: string,
  role: string
) => {
  return http.post(`${SERVICE_COMPANY}/${companyId}/roles`, { email, role });
};

const editUserInCompany = (
  companyId: string,
  accountId: string,
  role: string
) => {
  return http.patch(`${SERVICE_COMPANY}/${companyId}/roles/${accountId}`, {
    role,
  });
};

const removeUserInCompany = (companyId: string, accountId: string) => {
  return http.delete(`${SERVICE_COMPANY}/${companyId}/roles/${accountId}`);
};

const getAllTokens = (companyId: string) => {
  return http.get(`${SERVICE_API}/${companyId}/tokens`);
};

const createToken = (companyId: string, description: string) => {
  return http.post(`${SERVICE_API}/${companyId}/tokens`, {
    description,
  });
};

const removeToken = (companyId: string, tokenId: string) => {
  return http.delete(`${SERVICE_API}/${companyId}/tokens/${tokenId}`);
};

export default {
  getAll,
  create,
  update,
  remove,
  getOne,
  getUsersInCompany,
  createUserInCompany,
  editUserInCompany,
  removeUserInCompany,
  createToken,
  removeToken,
  getAllTokens,
};
