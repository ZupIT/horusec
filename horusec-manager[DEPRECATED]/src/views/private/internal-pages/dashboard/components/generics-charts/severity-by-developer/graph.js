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

import { Doughnut } from 'vue-chartjs'
import { ColorsBySeverity } from '@/utils/severity'
import randomcolor from 'randomcolor'

export default {
  extends: Doughnut,
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
      maintainAspectRatio: false,
      legend: {
        onClick: (e) => e.stopPropagation()
      },
      tooltips: {
        callbacks: {
          label: function (item, data) {
            var label = data.datasets[item.datasetIndex].labels[item.index]
            var value = data.datasets[item.datasetIndex].data[item.index]
            return label + ': ' + value
          }
        }
      }
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
      let dataSets = []
      if (this.dataAndLabels && this.dataAndLabels.data && this.dataAndLabels.data.length) {
        const dataSet = {
          backgroundColor: [],
          labels: this.dataAndLabels.labels,
          data: this.dataAndLabels.data.map(item => item.total)
        }
        const severityDataset = {
          labels: [],
          data: [],
          backgroundColor: [],
          borderColor: [],
          borderWidth: 5
        }
        this.dataAndLabels.data.forEach(element => {
          const colorLanguage = randomcolor()
          dataSet.backgroundColor.push(colorLanguage)
          
          if (element.low !== 0) {
            let colorSeverity = ColorsBySeverity['LOW']
            severityDataset.backgroundColor.push(colorSeverity)
            severityDataset.borderColor.push(colorLanguage)
            severityDataset.labels.push('LOW')
            severityDataset.data.push(element.low)
          }
          
          if (element.medium !== 0) {
            let colorSeverity = ColorsBySeverity['MEDIUM']
            severityDataset.backgroundColor.push(colorSeverity)
            severityDataset.borderColor.push(colorLanguage)
            severityDataset.labels.push('MEDIUM')
            severityDataset.data.push(element.medium)
          }

          if (element.high !== 0) {
            let colorSeverity = ColorsBySeverity['HIGH']
            severityDataset.backgroundColor.push(colorSeverity)
            severityDataset.borderColor.push(colorLanguage)
            severityDataset.labels.push('HIGH')
            severityDataset.data.push(element.high)
          }

          if (element.noSec !== 0) {
            let colorSeverity = ColorsBySeverity['NOSEC']
            severityDataset.backgroundColor.push(colorSeverity)
            severityDataset.borderColor.push(colorLanguage)
            severityDataset.labels.push('NOSEC')
            severityDataset.data.push(element.noSec)
          }

          if (element.audit !== 0) {
            let colorSeverity = ColorsBySeverity['AUDIT']
            severityDataset.backgroundColor.push(colorSeverity)
            severityDataset.borderColor.push(colorLanguage)
            severityDataset.labels.push('AUDIT')
            severityDataset.data.push(element.audit)
          }

          if (element.info !== 0) {
            let colorSeverity = ColorsBySeverity['INFO']
            severityDataset.backgroundColor.push(colorSeverity)
            severityDataset.borderColor.push(colorLanguage)
            severityDataset.labels.push('INFO')
            severityDataset.data.push(element.info)
          }
          
        })
        dataSets.push(dataSet, severityDataset)
      }

      return dataSets
    }
  }
}
