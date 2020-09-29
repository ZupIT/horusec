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

import { mapActions, mapGetters } from 'vuex'
import GenericsCharts from '../generics-charts/index.vue'

export default {
  components: {
    GenericsCharts
  },
  data: () => ({
    isLoading: false,
    repositoryIdSelected: '',
    repositories: []
  }),
  computed: {
    ...mapGetters([
      'getterSelectedCompany',
      'getterLoadingChartTotalRepositories',
      'getterLoadingChartAllSeverity',
      'getterLoadingChartSeverityByDeveloper',
      'getterLoadingChartSeverityByLanguage',
      'getterLoadingChartSeverityByRepository',
      'getterLoadingChartSeverityByTime',
      'getterLoadingChartSeverityDetails',
      'getterLoadingChartTotalDevelopers'
    ]),
    isLoadingCharts () {
      const validation = (
        this.getterLoadingChartTotalRepositories ||
        this.getterLoadingChartAllSeverity ||
        this.getterLoadingChartSeverityByDeveloper ||
        this.getterLoadingChartSeverityByLanguage ||
        this.getterLoadingChartSeverityByRepository ||
        this.getterLoadingChartSeverityByTime ||
        this.getterLoadingChartSeverityDetails ||
        this.getterLoadingChartTotalDevelopers ||
        this.isLoading
      )

      this.$emit('set-disabled-search', validation)

      return validation
    }
  },
  async beforeDestroy () {
    const query = Object.assign({}, this.$route.query)
    if (query.repositoryId) {
      delete query.repositoryId
      await this.$router.push({ query })
    }
  },
  async mounted () {
    await this.getAllRepositories()

    if (this.$route.query.repositoryId) {
      this.repositoryIdSelected = this.$route.query.repositoryId
    } else if (this.repositories.length > 0) {
      this.repositoryIdSelected = this.repositories[0].repositoryID
    }

    this.updateCharts()
  },
  methods: {
    ...mapActions([
      'actionGetAllRepository'
    ]),
    async getAllRepositories () {
      this.isLoading = true
      this.repositories = []

      await this.actionGetAllRepository(this.getterSelectedCompany.companyID)
        .then((result) => {
          this.repositories = result.data.content
        })
        .catch((err) => this.handleError(err, {}))

      this.isLoading = false
    },
    async updateCharts () {
      if (this.$route.query.repositoryId !== this.repositoryIdSelected) {
        this.isLoading = true
        const query = Object.assign({}, this.$route.query)
        query.repositoryId = this.repositoryIdSelected
        await this.$router.push({ query })
        this.isLoading = false
      }
    }
  }
}