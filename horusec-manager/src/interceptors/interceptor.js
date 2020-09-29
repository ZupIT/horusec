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
import Moment from 'moment'
import environments from '../environments/environments'

export const refreshTokenFunction = (accessToken, refreshToken) => {
  return axios.post(`${environments.SERVICE_ACCOUNT}/api/account/renew-token`, refreshToken, { headers: { Authorization: accessToken, 'Content-type': 'text/plain' } })
    .then((response) => {
      if (response.status === 200 && response.data.content) {
        Vue.prototype.$globalStore.commit('SET_ACCESS_TOKEN', `Bearer ${response.data.content.accessToken}`)
        Vue.prototype.$globalStore.commit('SET_REFRESH_TOKEN', response.data.content.refreshToken)
        Vue.prototype.$globalStore.commit('SET_ACCESS_TOKEN_EXPIRES_AT', response.data.content.expiresAt)
      }
    })
    .catch(async (err) => {
      await Vue.prototype.$globalStore.dispatch('actionLogout', Vue.prototype.$globalRouter.currentRoute.fullPath)
      return Promise.reject(err)
    })
}

/**
 * @param {object} authorization
 *
 * @return {axios}
*/
export const HTTP = (forceRefreshTokenAfterRequest) => {
  const accessToken = Vue.prototype.$globalStore.getters.getterAccessToken
  const refreshToken = Vue.prototype.$globalStore.getters.getterRefreshToken
  const expiresAt = Vue.prototype.$globalStore.getters.getterAccessTokenExpiresAt

  if (!accessToken) {
    return Promise.reject(new Error('Access_token not exist'))
  }

  const http = axios.create({ headers: { Authorization: accessToken } })

  http.interceptors.request.use(async (config) => {
    const diff = Moment().diff(expiresAt, 'minutes')

    if (Math.abs(diff) <= 10) {
      await refreshTokenFunction(accessToken, refreshToken)
    }

    return config
  }, (error) => Promise.reject(error))

  http.interceptors.response.use(async (config) => {
    if (forceRefreshTokenAfterRequest) {
      await refreshTokenFunction(accessToken, refreshToken)
    }

    return config
  }, async (error) => {
    if (!error.response) {
      return Promise.reject(error)
    }

    if (error.response.status === 401) {
      await Vue.prototype.$globalStore.dispatch('actionLogout', Vue.prototype.$globalRouter.currentRoute.fullPath)
    }
    return Promise.reject(error.response)
  })
  return http
}
