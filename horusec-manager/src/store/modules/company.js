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

export const SET_COMPANY_SELECTED = 'SET_COMPANY_SELECTED'
export const CLEAN_COMPANY_STORE = 'CLEAN_COMPANY_STORE'

const state = {
  selectedCompany: {
    companyID: '',
    name: '',
    description: ''
  }
}

const getters = {
  getterSelectedCompany: (state) => state.selectedCompany
}

const mutations = {
  [SET_COMPANY_SELECTED] (state, value) {
    state.selectedCompany = value
  },
  [CLEAN_COMPANY_STORE] (state) {
    state.selectedCompany = {
      companyID: '',
      name: '',
      description: ''
    }
  }
}

const actions = {
  /**
   * [/api/companies]
   * @method POST
   *
   * @param {string} name
   *
   * @return {Promise}
  */
  actionCreateCompany (_, name) {
    const body = { name }

    return HTTP().post(`${environments.SERVICE_ACCOUNT}/api/companies`, body)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  },
  /**
   * [/api/companies]
   * @method GET
   *
   * @return {Promise}
  */
  actionGetAllCompany () {
    return HTTP().get(`${environments.SERVICE_ACCOUNT}/api/companies`)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  },
  /**
   * [/api/companies/:id]
   * @method GET
   *
   * @param {string} name
   *
   * @return {Promise}
  */
  actionGetOneCompany ({ commit }, id) {
    return HTTP().get(`${environments.SERVICE_ACCOUNT}/api/companies/${id}`)
      .then((response) => {
        const company = {
          companyID: response.data.content.companyID,
          name: response.data.content.name,
          description: response.data.content.description
        }

        commit(SET_COMPANY_SELECTED, company)
        commit('SET_ROLE_USER_LOGGED', response.data.content.role)
        Promise.resolve(response)
      })
      .catch((err) => Promise.reject(err))
  },
  /**
   * [/api/companies/:id]
   * @method PATCH
   *
   * @param {object} params
   * @param {string} params.name
   * @param {string} params.id
   *
   * @return {Promise}
  */
  actionUpdateCompany (_, params) {
    const body = {
      name: params.name
    }

    return HTTP().patch(`${environments.SERVICE_ACCOUNT}/api/companies/${params.id}`, body)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  },
  /**
   * [/api/companies/:id]
   * @method DELETE
   *
   * @param {string} id
   *
   * @return {Promise}
  */
  actionDeleteCompany (_, id) {
    return HTTP().delete(`${environments.SERVICE_ACCOUNT}/api/companies/${id}`)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  },
  /**
   * [/api/companies/:companyId/roles]
   * @method GET
   *
   * @param {string} companyId
   *
   * @return {Promise}
  */
  actionGetAllUsersInCompany (_, companyId) {
    return HTTP().get(`${environments.SERVICE_ACCOUNT}/api/companies/${companyId}/roles`)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  },

  /**
   * [/api/companies/:companyId/roles]
   * @method POST
   *
   * @param {object} params
   * @param {string} params.companyId
   * @param {string} params.accountId
   * @param {string} params.role
   *
   * @return {Promise}
  */
  actionCreateUserInCompany (_, params) {
    const body = {
      email: params.email,
      role: params.role
    }

    return HTTP().post(`${environments.SERVICE_ACCOUNT}/api/companies/${params.companyId}/roles`, body)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  },
  /**
   * [/api/companies/:companyId/roles/:accountId]
   * @method PATCH
   *
   * @param {object} params
   * @param {string} params.companyId
   * @param {string} params.accountId
   * @param {string} params.role
   *
   * @return {Promise}
  */
  actionEditUserInCompany (_, params) {
    const body = {
      role: params.role
    }

    return HTTP().patch(`${environments.SERVICE_ACCOUNT}/api/companies/${params.companyId}/roles/${params.accountId}`, body)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  },
  /**
   * [/api/companies/:companyId/roles/:accountId]
   * @method DELETE
   *
   * @param {object} params
   * @param {string} params.companyId
   * @param {string} params.accountId
   *
   * @return {Promise}
  */
  actionRemoveUserInCompany (_, params) {
    return HTTP().delete(`${environments.SERVICE_ACCOUNT}/api/companies/${params.companyId}/roles/${params.accountId}`)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  }
}

export default {
  state,
  getters,
  mutations,
  actions
}
