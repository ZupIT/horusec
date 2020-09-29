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

import { HTTP } from '../../interceptors/interceptor'
import environments from '../../environments/environments'

const actions = {
  /**
   * [/api/companies/:companyId/repositories]
   * @method GET
   *
   * @param {string} companyId
   *
   * @return {Promise}
  */
  actionGetAllRepository (_, companyId) {
    return HTTP().get(`${environments.SERVICE_ACCOUNT}/api/companies/${companyId}/repositories`)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  },
  /**
   * [/api/companies/:companyId/repositories]
   * @method POST
   *
   * @param {object} params
   * @param {string} params.companyId
   * @param {string} params.description
   * @param {string} params.name
   *
   * @return {Promise}
  */
  actionCreateRepository (_, params) {
    const body = {
      description: params.description,
      name: params.name
    }

    return HTTP(true).post(`${environments.SERVICE_ACCOUNT}/api/companies/${params.companyId}/repositories`, body)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  },
  /**
   * [/api/companies/:companyId/repositories/:repositoryId]
   * @method PATCH
   *
   * @param {object} params
   * @param {string} params.repositoryId
   * @param {string} params.companyId
   * @param {string} params.userId
   * @param {string} params.permission
   *
   * @return {Promise}
  */
  actionEditRepository (_, params) {
    const body = {
      description: params.description,
      name: params.name
    }

    return HTTP(true).patch(`${environments.SERVICE_ACCOUNT}/api/companies/${params.companyId}/repositories/${params.repositoryId}`, body)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  },
  /**
   * [/api/companies/:companyId/repositories/:repositoryId]
   * @method DELETE
   *
   * @param {object} params
   * @param {string} params.companyId
   * @param {string} params.repositoryId
   *
   * @return {Promise}
  */
  actionRemoveRepository (_, params) {
    return HTTP(true).delete(`${environments.SERVICE_ACCOUNT}/api/companies/${params.companyId}/repositories/${params.repositoryId}`)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  },
  /**
   * [/api/companies/:companyId/repositories/:repositoryId/roles]
   * @method GET
   *
   * @param {object} params
   * @param {string} params.companyId
   * @param {string} params.repositoryId
   *
   * @return {Promise}
  */
  actionGetAllUsersInRepository (_, params) {
    return HTTP().get(`${environments.SERVICE_ACCOUNT}/api/companies/${params.companyId}/repositories/${params.repositoryId}/roles`)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  },
  /**
   * [/api/companies/:companyId/repositories/:repositoryId/roles/:accountId]
   * @method PATCH
   *
   * @param {object} params
   * @param {string} params.companyId
   * @param {string} params.repositoryId
   * @param {string} params.accountId
   * @param {string} params.email
   * @param {string} params.role
   *
   * @return {Promise}
  */
  actionUpdateUserInRepository (_, params) {
    const body = {
      role: params.role
    }

    return HTTP(true).patch(`${environments.SERVICE_ACCOUNT}/api/companies/${params.companyId}/repositories/${params.repositoryId}/roles/${params.accountId}`, body)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  },
  /**
   * [/api/companies/:companyId/repositories/:repositoryId/roles]
   * @method POST
   *
   * @param {object} params
   * @param {string} params.companyId
   * @param {string} params.repositoryId
   * @param {string} params.email
   * @param {string} params.role
   *
   * @return {Promise}
  */
  actionCreateUserInRepository (_, params) {
    const body = {
      email: params.email,
      role: params.role
    }

    return HTTP(true).post(`${environments.SERVICE_ACCOUNT}/api/companies/${params.companyId}/repositories/${params.repositoryId}/roles`, body)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  },
  /**
   * [/api/companies/:companyId/repositories/:repositoryId/roles/:accountId]
   * @method DELETE
   *
   * @param {object} params
   * @param {string} params.companyId
   * @param {string} params.repositoryId
   * @param {string} params.accountId
   *
   * @return {Promise}
  */
  actionDeleteUserInRepository (_, params) {
    return HTTP(true).delete(`${environments.SERVICE_ACCOUNT}/api/companies/${params.companyId}/repositories/${params.repositoryId}/roles/${params.accountId}`)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  },
  /**
   * [/api/companies/:companyId/repositories/:repositoryId/tokens]
   * @method GET
   *
   * @param {object} params
   * @param {string} params.repositoryId
   * @param {string} params.companyId
   *
   * @return {Promise}
  */
  actionGetAllTokensInRepository (_, params) {
    return HTTP().get(`${environments.SERVICE_API}/api/companies/${params.companyId}/repositories/${params.repositoryId}/tokens`)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  },
  /**
   * [/api/companies/:companyId/repositories/:repositoryId/tokens]
   * @method POST
   *
   * @param {object} params
   * @param {string} params.repositoryId
   * @param {string} params.companyId
   * @param {string} params.description
   *
   * @return {Promise}
  */
  actionCreateTokensInRepository (_, params) {
    const body = {
      description: params.description
    }

    return HTTP(true).post(`${environments.SERVICE_API}/api/companies/${params.companyId}/repositories/${params.repositoryId}/tokens`, body)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  },
  /**
   * [/api/companies/:companyId/repositories/:repositoryId/tokens/:tokenId]
   * @method DELETE
   *
   * @param {object} params
   * @param {string} params.repositoryId
   * @param {string} params.companyId
   * @param {string} params.tokenId
   *
   * @return {Promise}
  */
  actionDeleteTokensInRepository (_, params) {
    return HTTP(true).delete(`${environments.SERVICE_API}/api/companies/${params.companyId}/repositories/${params.repositoryId}/tokens/${params.tokenId}`)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  }
}

export default {
  actions
}
