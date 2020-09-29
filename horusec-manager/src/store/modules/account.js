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

import axios from 'axios'
import Vue from 'vue'
// import { HTTP } from '../../interceptors/interceptor'
import environments from '../../environments/environments'

export const CLEAN_ACCOUNT_STORE = 'CLEAN_ACCOUNT_STORE'
export const SET_ACCESS_TOKEN = 'SET_ACCESS_TOKEN'
export const SET_REFRESH_TOKEN = 'SET_REFRESH_TOKEN'
export const SET_ACCESS_TOKEN_EXPIRES_AT = 'SET_ACCESS_TOKEN_EXPIRES_AT'
export const SET_EMAIL_USER_LOGGED = 'SET_EMAIL_USER_LOGGED'
export const SET_ROLE_USER_LOGGED = 'SET_ROLE_USER_LOGGED'

const state = {
  accessToken: '',
  refreshToken: '',
  accessTokenExpiresAt: '',
  userLogged: {
    email: '',
    role: ''
  }
}

const getters = {
  getterAccessToken: (state) => state.accessToken,
  getterRefreshToken: (state) => state.refreshToken,
  getterAccessTokenExpiresAt: (state) => state.accessTokenExpiresAt,
  getterUserLogged: (state) => state.userLogged
}

const mutations = {
  [SET_ACCESS_TOKEN] (state, value) {
    state.accessToken = value
  },
  [SET_REFRESH_TOKEN] (state, value) {
    state.refreshToken = value
  },
  [SET_ACCESS_TOKEN_EXPIRES_AT] (state, value) {
    state.accessTokenExpiresAt = value
  },
  [SET_EMAIL_USER_LOGGED] (state, value) {
    state.userLogged.email = value
  },
  [SET_ROLE_USER_LOGGED] (state, value) {
    state.userLogged.role = value
  },
  [CLEAN_ACCOUNT_STORE] (state) {
    state.accessToken = ''
    state.refreshToken = ''
    state.accessTokenExpiresAt = ''
    state.userLogged = {
      email: '',
      role: ''
    }
  }
}

const actions = {
  /**
   * [/api/account/logout]
   * @method POST
   *
   * @param {string} redirectUrl optional
   *
   * @return {Promise}
  */
  actionLogout ({ dispatch, getters }, redirectUrl) {
    const body = {}
    const config = {
      headers: {
        Authorization: getters.getterAccessToken
      }
    }

    return axios.post(`${environments.SERVICE_ACCOUNT}/api/account/logout`, body, config)
      .finally(() => {
        dispatch('cleanStorage')
        if (Vue.prototype.$globalRouter.currentRoute.name !== 'login') {
          setTimeout(() => {
            if (redirectUrl && redirectUrl.length > 0) {
              Vue.prototype.$globalRouter.push({ name: 'login', query: { redirectUrl } })
            } else {
              Vue.prototype.$globalRouter.push({ name: 'login' })
            }
          }, 100)
        }
      })
  },
  /**
   * [/api/account/login]
   * @method POST
   *
   * @param {object} params
   * @param {string} params.email
   * @param {string} params.password
   *
   * @return {Promise}
  */
  actionLogin ({ commit }, params) {
    const body = {
      email: params.email,
      password: params.password
    }

    return axios.post(`${environments.SERVICE_ACCOUNT}/api/account/login`, body)
      .then((response) => {
        commit(SET_ACCESS_TOKEN, `Bearer ${response.data.content.accessToken}`)
        commit(SET_REFRESH_TOKEN, response.data.content.refreshToken)
        commit(SET_ACCESS_TOKEN_EXPIRES_AT, response.data.content.expiresAt)
        commit(SET_EMAIL_USER_LOGGED, response.data.content.email)
        return Promise.resolve(response.data)
      })
      .catch((err) => Promise.reject(err.response))
  },
  /**
   * [/api/account/create-account]
   * @method POST
   *
   * @param {object} params
   * @param {string} params.username
   * @param {string} params.password
   * @param {string} params.email
   *
   * @return {Promise}
  */
  actionCreateAccount (_, params) {
    const body = {
      username: params.username,
      email: params.email,
      password: params.password
    }

    return axios.post(`${environments.SERVICE_ACCOUNT}/api/account/create-account`, body)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  },
  /**
   * [/api/account/send-code]
   * @method POST
   *
   * @param {object} params
   * @param {string} params.email
   *
   * @return {Promise}
  */
  actionRecoveryPassSendEmail (_, params) {
    const body = {
      email: params.email
    }

    return axios.post(`${environments.SERVICE_ACCOUNT}/api/account/send-code`, body)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  },
  /**
   * [/api/account/validate-code]
   * @method POST
   *
   * @param {object} params
   * @param {string} params.email
   * @param {string} params.code
   *
   * @return {Promise}
  */
  actionRecoveryPassSendCode (_, params) {
    const body = {
      email: params.email,
      code: params.code
    }

    return axios.post(`${environments.SERVICE_ACCOUNT}/api/account/validate-code`, body)
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
  },
  /**
   * [/api/account/change-password]
   * @method POST
   *
   * @param {object} params
   * @param {object} params.password
   * @param {object} params.token
   *
   * @return {Promise}
  */
  actionRecoveryPassSendNewPassword (_, params) {
    const body = params.password
    const config = {
      headers: {
        Authorization: params.token,
        'Content-Type': 'text/plain'
      }
    }

    return axios.post(`${environments.SERVICE_ACCOUNT}/api/account/change-password`, body, config)
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
