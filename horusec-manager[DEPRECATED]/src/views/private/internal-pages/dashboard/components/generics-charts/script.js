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

import ChartTotalRepositories from './total-repositories/index.vue'
import ChartAllSeverity from './all-severity/index.vue'
import ChartSeverityByDeveloper from './severity-by-developer/index.vue'
import ChartSeverityByLanguage from './severity-by-language/index.vue'
import ChartSeverityByRepository from './severity-by-repository/index.vue'
import ChartSeverityByTime from './severity-by-time/index.vue'
import ChartSeverityDetailsTable from './severity-details-table/index.vue'
import ChartTotalDevelopers from './total-developers/index.vue'

export default {
  props: {
    disableChartTotalRepositories: {
      type: Boolean,
      required: false
    },
    disableChartSeverityByRepositories: {
      type: Boolean,
      required: false
    }
  },
  components: {
    ChartTotalRepositories,
    ChartTotalDevelopers,
    ChartAllSeverity,
    ChartSeverityByDeveloper,
    ChartSeverityByLanguage,
    ChartSeverityByRepository,
    ChartSeverityByTime,
    ChartSeverityDetailsTable
  }
}
