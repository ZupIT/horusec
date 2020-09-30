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

import { Pie } from 'vue-chartjs'
import { ColorsBySeverity, GetSeverityList, GetPositionByLabel } from '@/utils/severity'
export default {
  extends: Pie,
  props: {
    labelsAndValues: {
      type: Array, // [{label: 'NOSEC', value: 10}]
      required: true
    }
  },
  mounted () {
    this.renderChart({
      labels: GetSeverityList(),
      datasets: this.getDatasets()
    }, {
      responsive: true,
      maintainAspectRatio: false
    })
  },
  methods: {
    getDatasets () {
      let datasets = [{
        backgroundColor: [],
        data: []
      }]

      GetSeverityList().forEach((severity) => {
        datasets[0].backgroundColor.push(ColorsBySeverity[severity])
        datasets[0].data.push(0)
      })

      if (this.labelsAndValues && this.labelsAndValues.length) {
        this.labelsAndValues.forEach((item) => {
          const colorSeverity = ColorsBySeverity[item.label]
          const index = GetPositionByLabel(item.label)
          datasets[0].backgroundColor[index] = colorSeverity
          datasets[0].data[index] = item.value
        })
      }

      return datasets
    }
  }
}
