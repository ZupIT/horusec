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

export default {
  extends: Pie,
  props: {
    dataAndLabels: {
      type: Object, // {labels: ['NOSEC'], data: [10]}
      required: true
    }
  },
  mounted () {
    this.renderChart({
      labels: this.getLabels(),
      datasets: this.getDatasets()
    }, {
      responsive: true,
      maintainAspectRatio: false
    })
  },
  methods: {
    getLabels () {
      if (this.dataAndLabels && this.dataAndLabels.labels && this.dataAndLabels.labels.length) {
        return this.dataAndLabels.labels
      }
      return []
    },
    getDatasets () {
      const color = {
        NOSEC: 'rgba(0, 171, 255, 0.87)',
        LOW: 'rgba(234, 234, 140, 1)',
        MEDIUM: 'rgb(234, 193, 140)',
        HIGH: 'rgb(234, 140, 140)'
      }
      let dataSets = []

      if (this.dataAndLabels && this.dataAndLabels.data && this.dataAndLabels.data.length) {
        dataSets = [{
          backgroundColor: color[this.dataAndLabels.severity],
          data: this.dataAndLabels.data
        }]
      }

      return dataSets
    }
  }
}
