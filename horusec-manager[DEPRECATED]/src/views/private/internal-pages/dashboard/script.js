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

import { mapGetters } from 'vuex'
import CompanyCharts from './components/company-charts/index.vue'
import RepositoryCharts from './components/repository-charts/index.vue'
import StartDateEndDatePicker from '@/components/start-date-end-date-picker/index.vue'

export default {
  components: {
    CompanyCharts,
    RepositoryCharts,
    StartDateEndDatePicker
  },
  data: () => ({
    indexTabSelected: 0,
    disabledSearch: false,
    isLoading: false
  }),
  mounted () {
    if (parseInt(this.$route.query.indexTabSelected) + 1 <= this.getAllTabs.length) {
      this.indexTabSelected = parseInt(this.$route.query.indexTabSelected)
    }

    this.setTabSelected(this.indexTabSelected)
  },
  async beforeDestroy () {
    await this.$router.replace({ name: this.$route.name, params: this.$route.params, query: { companyId: this.$route.query.companyId } })
  },
  computed: {
    ...mapGetters([
      'getterSelectedCompany'
    ]),
    getAllTabs () {
      return [
        {
          label: this.$i18n.t('dashboard.tabs.company_tab'),
          type: 'company'
        },
        {
          label: this.$i18n.t('dashboard.tabs.repository_tab'),
          type: 'repository'
        }
      ]
    }
  },
  methods: {
    async setTabSelected (event, updateOnClick) {
      await this.updateRouter(event)

      if (updateOnClick) {
        this.isLoading = true

        setTimeout(() => {
          this.isLoading = false
        }, 250)
      }
    },
    async updateRouter (event) {
      if (this.$route.query.indexTabSelected !== event.toString()) {
        this.isLoading = true
        const query = Object.assign({}, this.$route.query)
        query.indexTabSelected = event
        await this.$router.push({ query })
        this.isLoading = false
      }
    }
  }
}
