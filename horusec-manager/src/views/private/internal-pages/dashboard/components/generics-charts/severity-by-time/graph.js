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

import { Line } from 'vue-chartjs'
import Moment from 'moment'
import { ColorsBySeverity } from '@/utils/severity'
import { mapGetters } from 'vuex'

export default {
  extends: Line,
  props: {
    dataAndLabels: {
      type: Object, // {labels: ['30/06/2020 14:30:50'], data: [150]}
      required: true
    }
  },
  mounted () {
    setTimeout(() => {
      this.renderChart({
        labels: this.getLabels(),
        datasets: this.getDatasets()
      },
      {
        responsive: true,
        maintainAspectRatio: false,
        tooltips: {
          mode: 'index',
          intersect: false
        },
        hover: {
          mode: 'nearest',
          intersect: true
        },
        scales: {
          yAxes: [{
            ticks: {
              beginAtZero: true
            }
          }],
          x: {
            display: true
          },
          y: {
            display: true
          }
        }
      }
      )
    }, 500)
  },
  computed: {
    ...mapGetters([
      'getterLanguage'
    ])
  },
  methods: {
    getLabels () {
      let format = 'DD/MM/YYYY'
      if (this.getterLanguage !== 'pt-BR') {
        format = 'YYYY-MM-DD'
      }
      if (this.dataAndLabels && this.dataAndLabels.labels && this.dataAndLabels.labels.length) {
        return this.dataAndLabels.labels.map((item) => {
          const finded = this.dataAndLabels.data.find((d) => d.time === item)
          if (finded) {
            return `${Moment.utc(item).format(format)} = (${finded.total})`
          }
          return Moment.utc(item).format(format)
        })
      }
      return []
    },
    getDatasets () {
      let dataSets = []
      if (this.dataAndLabels && this.dataAndLabels.data && this.dataAndLabels.data.length) {
        const auditDataSet = {
          backgroundColor: ColorsBySeverity.AUDIT,
          label: 'Audit',
          data: []
        }
        const noSecDataSet = {
          backgroundColor: ColorsBySeverity.NOSEC,
          label: 'NoSec',
          data: []
        }
        const lowDataSet = {
          backgroundColor: ColorsBySeverity.LOW,
          label: 'Low',
          data: []
        }
        const midDataSet = {
          backgroundColor: ColorsBySeverity.MEDIUM,
          label: 'Medium',
          data: []
        }
        const highDataSet = {
          backgroundColor: ColorsBySeverity.HIGH,
          label: 'High',
          data: []
        }
        const infoDataSet = {
          backgroundColor: ColorsBySeverity.INFO,
          label: 'Info',
          data: []
        }

        this.dataAndLabels.data.forEach((item) => {
          infoDataSet.data = auditDataSet.data.concat(item.info)
          auditDataSet.data = auditDataSet.data.concat(item.audit)
          noSecDataSet.data = noSecDataSet.data.concat(item.noSec)
          lowDataSet.data = lowDataSet.data.concat(item.low)
          midDataSet.data = midDataSet.data.concat(item.medium)
          highDataSet.data = highDataSet.data.concat(item.high)
        })

        dataSets = dataSets.concat(auditDataSet, noSecDataSet, lowDataSet, midDataSet, highDataSet, infoDataSet)
      }
      
      return dataSets
    }
  }
}
