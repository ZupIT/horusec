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

import Moment from 'moment'
import { cloneDeep } from 'lodash'
import { v4 as uuidv4 } from 'uuid'

export default {
  props: {
    hasAction: {
      type: Boolean,
      default: false
    },
    disabled: {
      type: Boolean,
      default: false
    }
  },
  data: () => ({
    startDateID: `start-date-${uuidv4()}`,
    endDateID: `end-date-${uuidv4()}`,
    form: {
      valid: false,
      startDate: {
        isOpen: false,
        value: Moment().toISOString(),
        valueFormatted: '',
        rules: []
      },
      endDate: {
        isOpen: false,
        value: Moment().toISOString(),
        valueFormatted: '',
        rules: []
      }
    }
  }),
  computed: {
    getMinDate () {
      return Moment(cloneDeep(this.form.startDate.value)).toISOString()
    },
    getMaxDate () {
      return Moment(cloneDeep(this.form.endDate.value)).toISOString()
    },
    getStartDateFormatted () {
      if (this.$i18n.locale === 'pt-BR') {
        return Moment(cloneDeep(this.form.startDate.value)).format('DD/MM/YYYY')
      }
      if (this.$i18n.locale === 'en-US') {
        return Moment(cloneDeep(this.form.startDate.value)).format('YYYY/MM/DD')
      }
      return ''
    },
    getEndDateFormatted () {
      if (this.$i18n.locale === 'pt-BR') {
        return Moment(cloneDeep(this.form.endDate.value)).format('DD/MM/YYYY')
      }
      if (this.$i18n.locale === 'en-US') {
        return Moment(cloneDeep(this.form.endDate.value)).format('YYYY/MM/DD')
      }
      return ''
    }
  },
  mounted () {
    setTimeout(() => {
      this.emitChanges()
    }, 1000)
  },
  methods: {
    emitChanges () {
      if (!this.form.valid) {
        return
      }
      const content = {
        startDate: Moment(this.form.startDate.value).format('YYYY-MM-DD[T][00]:[00]:[00][Z]'),
        endDate: Moment(this.form.endDate.value).format('YYYY-MM-DD[T][23]:[59]:[59][Z]')
      }

      this.$eventBus.$emit('udpate-date', content)
    }
  }
}