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
import Vue from 'vue'

export const SET_CHART_LOADING = 'SET_CHART_LOADING'

const state = {
  isLoadingChartTotalRepositories: false,
  isLoadingChartAllSeverity: false,
  isLoadingChartSeverityByDeveloper: false,
  isLoadingChartSeverityByLanguage: false,
  isLoadingChartSeverityByRepository: false,
  isLoadingChartSeverityByTime: false,
  isLoadingChartSeverityDetails: false,
  isLoadingChartTotalDevelopers: false
}

const getters = {
  getterLoadingChartTotalRepositories: (state) => state.isLoadingChartTotalRepositories,
  getterLoadingChartAllSeverity: (state) => state.isLoadingChartAllSeverity,
  getterLoadingChartSeverityByDeveloper: (state) => state.isLoadingChartSeverityByDeveloper,
  getterLoadingChartSeverityByLanguage: (state) => state.isLoadingChartSeverityByLanguage,
  getterLoadingChartSeverityByRepository: (state) => state.isLoadingChartSeverityByRepository,
  getterLoadingChartSeverityByTime: (state) => state.isLoadingChartSeverityByTime,
  getterLoadingChartSeverityDetails: (state) => state.isLoadingChartSeverityDetails,
  getterLoadingChartTotalDevelopers: (state) => state.isLoadingChartTotalDevelopers
}

const mutations = {
  [SET_CHART_LOADING] (state, params) {
    Vue.set(state, `isLoading${params.chartName}`, params.value)
  }
}

const actions = {
  /**
   * [/api/dashboard/companies/:companyId/all-vulnerabilities?initialDate=:initialDate&finalDate=:finalDate]
   * @method GET
   * [/api/dashboard/repositories/:repositoryId/all-vulnerabilities?initialDate=:initialDate&finalDate=:finalDate]
   * @method GET
   *
   * @param {object} params
   * @param {string} params.companyId
   * @param {string} params.repositoryId
   * @param {string} params.startDate
   * @param {string} params.endDate
   *
   * @return {Promise}
  */
  actionGetChartAllSeverity ({ commit }, params) {
    commit(SET_CHART_LOADING, {
      chartName: 'ChartAllSeverity',
      value: true
    })

    let routePath = 'companies'
    let ID = params.companyId
    if (params.repositoryId.length) {
      routePath = 'repositories'
      ID = params.repositoryId
    }

    const queryString = {
      initialDate: params.startDate,
      finalDate: params.endDate
    }

    return HTTP().get(`${environments.SERVICE_ANALYTIC}/api/dashboard/${routePath}/${ID}/all-vulnerabilities`, { params: queryString })
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
      .finally(() => {
        commit(SET_CHART_LOADING, {
          chartName: 'ChartAllSeverity',
          value: false
        })
      })
  },
  /**
   * [/api/dashboard/companies/:companyId/vulnerabilities-by-author?initialDate=:initialDate&finalDate=:finalDate]
   * @method GET
   * [/api/dashboard/repositories/:repositoryId/vulnerabilities-by-author?initialDate=:initialDate&finalDate=:finalDate]
   * @method GET
   *
   * @param {object} params
   * @param {string} params.companyId
   * @param {string} params.repositoryId
   * @param {string} params.startDate
   * @param {string} params.endDate
   *
   * @return {Promise}
  */
  actionGetChartSeverityByDeveloper ({ commit }, params) {
    commit(SET_CHART_LOADING, {
      chartName: 'ChartSeverityByDeveloper',
      value: true
    })

    let routePath = 'companies'
    let ID = params.companyId
    if (params.repositoryId.length) {
      routePath = 'repositories'
      ID = params.repositoryId
    }

    const queryString = {
      initialDate: params.startDate,
      finalDate: params.endDate
    }

    return HTTP().get(`${environments.SERVICE_ANALYTIC}/api/dashboard/${routePath}/${ID}/vulnerabilities-by-author`, { params: queryString })
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
      .finally(() => {
        commit(SET_CHART_LOADING, {
          chartName: 'ChartSeverityByDeveloper',
          value: false
        })
      })
  },
  /**
   * [/api/dashboard/companies/:companyId/vulnerabilities-by-language?initialDate=:initialDate&finalDate=:finalDate]
   * @method GET
   * [/api/dashboard/repositories/:repositoryId/vulnerabilities-by-language?initialDate=:initialDate&finalDate=:finalDate]
   * @method GET
   *
   * @param {object} params
   * @param {string} params.companyId
   * @param {string} params.repositoryId
   * @param {string} params.startDate
   * @param {string} params.endDate
   *
   * @return {Promise}
  */
  actionGetChartSeverityByLanguage ({ commit }, params) {
    commit(SET_CHART_LOADING, {
      chartName: 'ChartSeverityByLanguage',
      value: true
    })

    let routePath = 'companies'
    let ID = params.companyId
    if (params.repositoryId.length) {
      routePath = 'repositories'
      ID = params.repositoryId
    }

    const queryString = {
      initialDate: params.startDate,
      finalDate: params.endDate
    }

    return HTTP().get(`${environments.SERVICE_ANALYTIC}/api/dashboard/${routePath}/${ID}/vulnerabilities-by-language`, { params: queryString })
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
      .finally(() => {
        commit(SET_CHART_LOADING, {
          chartName: 'ChartSeverityByLanguage',
          value: false
        })
      })
  },
  /**
   * [/api/dashboard/companies/:companyId/vulnerabilities-by-repository?initialDate=:initialDate&finalDate=:finalDate]
   * @method GET
   * [/api/dashboard/repositories/:repositoryId/vulnerabilities-by-repository?initialDate=:initialDate&finalDate=:finalDate]
   * @method GET
   *
   * @param {object} params
   * @param {string} params.companyId
   * @param {string} params.repositoryId
   * @param {string} params.startDate
   * @param {string} params.endDate
   *
   * @return {Promise}
  */
  actionGetChartSeverityByRepository ({ commit }, params) {
    commit(SET_CHART_LOADING, {
      chartName: 'ChartSeverityByRepository',
      value: true
    })

    let routePath = 'companies'
    let ID = params.companyId
    if (params.repositoryId.length) {
      routePath = 'repositories'
      ID = params.repositoryId
    }

    const queryString = {
      initialDate: params.startDate,
      finalDate: params.endDate
    }

    return HTTP().get(`${environments.SERVICE_ANALYTIC}/api/dashboard/${routePath}/${ID}/vulnerabilities-by-repository`, { params: queryString })
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
      .finally(() => {
        commit(SET_CHART_LOADING, {
          chartName: 'ChartSeverityByRepository',
          value: false
        })
      })
  },
  /**
   * [/api/dashboard/companies/:companyId/vulnerabilities-by-time?initialDate=:initialDate&finalDate=:finalDate]
   * @method GET
   * [/api/dashboard/repositories/:repositoryId/vulnerabilities-by-time?initialDate=:initialDate&finalDate=:finalDate]
   * @method GET
   *
   * @param {object} params
   * @param {string} params.companyId
   * @param {string} params.repositoryId
   * @param {string} params.startDate
   * @param {string} params.endDate
   *
   * @return {Promise}
  */
  actionGetChartSeverityByTime ({ commit }, params) {
    commit(SET_CHART_LOADING, {
      chartName: 'ChartSeverityByTime',
      value: true
    })

    let routePath = 'companies'
    let ID = params.companyId
    if (params.repositoryId.length) {
      routePath = 'repositories'
      ID = params.repositoryId
    }

    const queryString = {
      initialDate: params.startDate,
      finalDate: params.endDate
    }

    return HTTP().get(`${environments.SERVICE_ANALYTIC}/api/dashboard/${routePath}/${ID}/vulnerabilities-by-time`, { params: queryString })
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
      .finally(() => {
        commit(SET_CHART_LOADING, {
          chartName: 'ChartSeverityByTime',
          value: false
        })
      })
  },
  /**
   * [/api/dashboard/companies/:companyId/details?query=:queryGraphQL&page=:page&size=:size]
   * @method GET
   * [/api/dashboard/repositories/:repositoryId/details?query=:queryGraphQL&page=:page&size=:size]
   * @method GET
   *
   * @param {object} params
   * @param {string} params.companyId
   * @param {string} params.repositoryId
   * @param {string} params.startDate
   * @param {string} params.endDate
   * @param {number} params.page
   * @param {number} params.size
   *
   * @return {Promise}
  */
  actionGetChartSeverityDetails ({ commit }, params) {
    commit(SET_CHART_LOADING, {
      chartName: 'ChartSeverityDetails',
      value: true
    })

    let filter = `companyID: "${params.companyId}"`
    if (params.repositoryId.length) {
      filter = `repositoryID: "${params.repositoryId}"`
    }

    const query = `{
      totalItems(${filter}, initialDate: "${params.startDate}", finalDate: "${params.endDate}")
      analysis (${filter}, initialDate: "${params.startDate}", finalDate: "${params.endDate}"){
        repositoryName
        companyName
        vulnerability {
          line
          column
          confidence
          file
          code
          details
          type
          vulnerableBelow
          version
          securityTool
          language
          severity
          vulnHash
          commitAuthor {
            author
            email
          }
        }
      }
    }`

    let routePath = 'companies'
    let ID = params.companyId
    if (params.repositoryId.length) {
      routePath = 'repositories'
      ID = params.repositoryId
    }

    const queryString = {
      query,
      page: params.page,
      size: params.size
    }

    return HTTP().get(`${environments.SERVICE_ANALYTIC}/api/dashboard/${routePath}/${ID}/details`, { params: queryString })
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
      .finally(() => {
        commit(SET_CHART_LOADING, {
          chartName: 'ChartSeverityDetails',
          value: false
        })
      })
  },
  /**
   * [/api/dashboard/companies/:companyId/total-developers?initialDate=:initialDate&finalDate=:finalDate]
   * @method GET
   * [/api/dashboard/repositories/:repositoryId/total-developers?initialDate=:initialDate&finalDate=:finalDate]
   * @method GET
   *
   * @param {object} params
   * @param {string} params.companyId
   * @param {string} params.repositoryId
   * @param {string} params.startDate
   * @param {string} params.endDate
   *
   * @return {Promise}
  */
  actionGetChartTotalDevelopers ({ commit }, params) {
    commit(SET_CHART_LOADING, {
      chartName: 'ChartTotalDevelopers',
      value: true
    })

    let routePath = 'companies'
    let ID = params.companyId
    if (params.repositoryId) {
      routePath = 'repositories'
      ID = params.repositoryId
    }

    const queryString = {
      initialDate: params.startDate,
      finalDate: params.endDate
    }

    return HTTP().get(`${environments.SERVICE_ANALYTIC}/api/dashboard/${routePath}/${ID}/total-developers`, { params: queryString })
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
      .finally(() => {
        commit(SET_CHART_LOADING, {
          chartName: 'ChartTotalDevelopers',
          value: false
        })
      })
  },
  /**
   * [/api/dashboard/companies/:companyId/total-repositories?initialDate=:initialDate&finalDate=:finalDate]
   * @method GET
   * [/api/dashboard/repositories/:repositoryId/total-repositories?initialDate=:initialDate&finalDate=:finalDate]
   * @method GET
   *
   * @param {object} params
   * @param {string} params.companyId
   * @param {string} params.repositoryId
   * @param {string} params.startDate
   * @param {string} params.endDate
   *
   * @return {Promise}
  */
  actionGetChartTotalRepositories ({ commit }, params) {
    commit(SET_CHART_LOADING, {
      chartName: 'ChartTotalRepositories',
      value: true
    })

    let routePath = 'companies'
    let ID = params.companyId
    if (params.repositoryId.length) {
      routePath = 'repositories'
      ID = params.repositoryId
    }

    const queryString = {
      initialDate: params.startDate,
      finalDate: params.endDate
    }

    return HTTP().get(`${environments.SERVICE_ANALYTIC}/api/dashboard/${routePath}/${ID}/total-repositories`, { params: queryString })
      .then((response) => Promise.resolve(response))
      .catch((err) => Promise.reject(err))
      .finally(() => {
        commit(SET_CHART_LOADING, {
          chartName: 'ChartTotalRepositories',
          value: false
        })
      })
  }
}

export default {
  state,
  getters,
  mutations,
  actions
}
