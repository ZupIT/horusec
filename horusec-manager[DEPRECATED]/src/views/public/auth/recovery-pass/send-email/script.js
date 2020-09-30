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

import FormValidations from '@/mixins/form-validations'
import { mapActions } from 'vuex'
import HorusecLogo from '@/components/horusec-logo/index.vue'

export default {
  components: {
    HorusecLogo
  },
  mixins: [
    FormValidations
  ],
  data: () => ({
    isLoading: false,
    form: {
      valid: false,
      email: {
        value: '',
        rules: []
      }
    }
  }),
  mounted () {
    this.form.email.rules = [
      v => this.validateFieldRequired(v),
      v => this.validateEmailInvalid(v)
    ]
  },
  methods: {
    ...mapActions([
      'actionRecoveryPassSendEmail'
    ]),
    submit () {
      if (!this.form.valid) {
        this.$toast.open({
          message: this.$i18n.t('globals.toast.invalid_form'),
          type: 'error'
        })
        return
      }
      this.isLoading = true

      this.actionRecoveryPassSendEmail({
        email: this.form.email.value
      })
        .then(() => {
          this.$toast.open({
            message: this.$i18n.t('recovery_password.form.toast_email_sent'),
            type: 'success'
          })
        })
        .catch((err) => this.handleError(err, {}))
        .finally(() => {
          this.$router.push({
            name: 'recovery-password-send-code',
            query: {
              email: this.form.email.value
            }
          })
          this.isLoading = false
        })
    },
    goToLogin () {
      this.$router.push({ name: 'login' })
    }
  }
}
