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

import http from 'config/axios';

import { SERVICE_ACCOUNT, SERVICE_API } from '../config/endpoints';
import { FilterVuln } from 'helpers/interfaces/FIlterVuln';
import { PaginationInfo } from 'helpers/interfaces/Pagination';
import { LDAPGroups } from 'helpers/interfaces/LDAPGroups';

const getAll = (companyId: string) => {
  return http.get(
    `${SERVICE_ACCOUNT}/account/companies/${companyId}/repositories`
  );
};

const create = (
  companyId: string,
  name: string,
  description: string,
  ldapGroups?: LDAPGroups
) => {
  return http.post(
    `${SERVICE_ACCOUNT}/account/companies/${companyId}/repositories`,
    {
      name,
      description,
      ...ldapGroups,
    }
  );
};

const update = (
  companyId: string,
  repositoryId: string,
  name: string,
  description: string,
  ldapGroups?: LDAPGroups
) => {
  return http.patch(
    `${SERVICE_ACCOUNT}/account/companies/${companyId}/repositories/${repositoryId}`,
    { name, description, ...ldapGroups }
  );
};

const remove = (companyId: string, repositoryId: string) => {
  return http.delete(
    `${SERVICE_ACCOUNT}/account/companies/${companyId}/repositories/${repositoryId}`
  );
};

const getAllTokens = (companyId: string, repositoryId: string) => {
  return http.get(
    `${SERVICE_API}/api/companies/${companyId}/repositories/${repositoryId}/tokens`
  );
};

const createToken = (
  companyId: string,
  repositoryId: string,
  description: string
) => {
  return http.post(
    `${SERVICE_API}/api/companies/${companyId}/repositories/${repositoryId}/tokens`,
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
    `${SERVICE_API}/api/companies/${companyId}/repositories/${repositoryId}/tokens/${tokenId}`
  );
};

const getUsersInRepository = (companyId: string, repositoryId: string) => {
  return http.get(
    `${SERVICE_ACCOUNT}/account/companies/${companyId}/repositories/${repositoryId}/roles`
  );
};

const includeUser = (
  companyId: string,
  repositoryId: string,
  email: string,
  role: string
) => {
  return http.post(
    `${SERVICE_ACCOUNT}/account/companies/${companyId}/repositories/${repositoryId}/roles`,
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
    `${SERVICE_ACCOUNT}/account/companies/${companyId}/repositories/${repositoryId}/roles/${accountId}`
  );
};

const updateUserRole = (
  companyId: string,
  repositoryId: string,
  accountId: string,
  role: string
) => {
  return http.patch(
    `${SERVICE_ACCOUNT}/account/companies/${companyId}/repositories/${repositoryId}/roles/${accountId}`,
    {
      role,
    }
  );
};

const getAllVulnerabilities = (
  filters: FilterVuln,
  pagination: PaginationInfo
) => {
  return http.get(
    `${SERVICE_API}/api/companies/${filters.companyID}/repositories/${filters.repositoryID}/management`,
    {
      params: {
        page: pagination.currentPage,
        size: pagination.pageSize,
        vulnSeverity: filters.vulnSeverity,
        vulnHash: filters.vulnHash,
        vulnType: filters.vulnType,
      },
    }
  );
};

const updateVulnerabilityType = (
  companyId: string,
  repositoryId: string,
  vulnerabilityId: string,
  type: string
) => {
  return http.put(
    `${SERVICE_API}/api/companies/${companyId}/repositories/${repositoryId}/management/${vulnerabilityId}/type`,
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
