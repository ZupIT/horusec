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

export default {
  data () {
    return {
      data: [],
      startDate: '',
      endDate: '',
      totalItems: 0,
      page: 1,
      size: 20
    }
  },
  computed: {
    ...mapGetters([
      'getterLoadingChartSeverityDetails',
      'getterSelectedCompany',
      'getterLanguage'
    ]),
    tableHeader () {
      return [
        { text: this.$i18n.t('dashboard.table.header_language'), value: 'vulnerability.language' },
        { text: this.$i18n.t('dashboard.table.header_severity'), value: 'vulnerability.severity' },
        { Text: this.$i18n.t('dashboard.table.header_file'), value: 'vulnerability.file' },
        { text: this.$i18n.t('dashboard.table.header_line'), value: 'vulnerability.line' },
        { text: this.$i18n.t('dashboard.table.vuln_hash'), value: 'vulnerability.vulnHash' },
        { text: this.$i18n.t('dashboard.table.header_code'), value: 'vulnerability.code' },
        { text: this.$i18n.t('dashboard.table.header_description'), value: 'vulnerability.details' },
        { text: this.$i18n.t('dashboard.table.header_author'), value: 'vulnerability.commitAuthor.author' }
      ]
    }
  },
  mounted () {
    this.$eventBus.$on('udpate-date', (event) => {
      this.startDate = event.startDate
      this.endDate = event.endDate
      this.getDataChart()
    })
  },
  beforeDestroy () {
    this.$eventBus.$off('udpate-date')
  },
  methods: {
    ...mapActions([
      'actionGetChartSeverityDetails'
    ]),
    getDataChart () {
      if (this.getterLoadingChartSeverityDetails) {
        return
      }

      const params = {
        companyId: this.getterSelectedCompany.companyID,
        repositoryId: this.$route.query.repositoryId || '',
        startDate: this.startDate,
        endDate: this.endDate,
        page: this.page,
        size: this.size
      }
      this.totalItems = 0
      this.data = []

      this.actionGetChartSeverityDetails(params)
        .then((result) => {
          const response = result.data.content.data
          this.totalItems = response.totalItems

          if (response && response.analysis && response.analysis.length) {
            this.data = response.analysis
          }
        })
        .catch((err) => this.handleError(err))
    }
  }
}
