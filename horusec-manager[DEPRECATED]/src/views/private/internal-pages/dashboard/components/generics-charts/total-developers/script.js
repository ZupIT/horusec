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
import Graph from './graph'

export default {
  components: {
    Graph
  },
  data: () => ({
    totalDevelopers: 0,
    startDate: '',
    endDate: ''
  }),
  computed: {
    ...mapGetters([
      'getterLoadingChartTotalDevelopers',
      'getterSelectedCompany'
    ])
  },
  mounted () {
    this.$eventBus.$on('udpate-date', (event) => {
      this.startDate = event.startDate
      this.endDate = event.endDate
      if (!this.getterLoadingChartTotalDevelopers) {
        this.getDataChart()
      }
    })
  },
  beforeDestroy () {
    this.$eventBus.$off('udpate-date')
  },
  methods: {
    ...mapActions([
      'actionGetChartTotalDevelopers'
    ]),
    getDataChart () {
      const params = {
        companyId: this.getterSelectedCompany.companyID,
        repositoryId: this.$route.query.repositoryId || '',
        startDate: this.startDate,
        endDate: this.endDate
      }
      this.totalDevelopers = 0

      this.actionGetChartTotalDevelopers(params)
        .then((result) => {
          if (!result.data.content) {
            return
          }
          this.totalDevelopers = result.data.content
        })
        .catch((err) => this.handleError(err))
    }
  }
}
