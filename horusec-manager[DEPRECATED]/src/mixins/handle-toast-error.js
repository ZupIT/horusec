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

export default {
  methods: {
    handleError (err, message) {
      console.error(err)
      if (!err) {
        this.$toast.open({
          message: this.$i18n.t('globals.toast.generic_toast_error'),
          type: 'error'
        })
      }

      if (message && Object.keys(message).length > 0) {
        if (message.custom && message.custom.length > 0) {
          return this.$toast.open({ type: 'error', message: this.$i18n.t(message.custom) })
        }

        if (message && !message[err.status]) {
          if (err.status === 403) {
            return this.$toast.open({ type: 'error', message: this.$i18n.t('globals.without_permission') })
          }

          return this.$toast.open({ type: 'error', message: this.$i18n.t('globals.toast.generic_toast_error') })
        }

        if (message[err.status] && message[err.status].length > 0) {
          return this.$toast.open({
            type: this.getTypeToastByStatus(err.status),
            message: this.$i18n.t(message[err.status])
          })
        }
      }

      return this.$toast.open({ type: 'error', message: this.$i18n.t('globals.toast.generic_toast_error') })
    },
    getTypeToastByStatus (status) {
      if (status >= 400 && status <= 499) {
        return 'warning'
      }

      return 'error'
    }
  }
}
