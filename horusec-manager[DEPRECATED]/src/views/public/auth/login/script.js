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
  mixins: [
    FormValidations
  ],
  components: {
    HorusecLogo
  },
  data: () => ({
    isLoading: false,
    form: {
      valid: false,
      email: {
        value: '',
        rules: []
      },
      password: {
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
    this.form.password.rules = [
      v => this.validateFieldRequired(v)
    ]
  },
  methods: {
    ...mapActions([
      'actionLogin'
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

      this.actionLogin({
        email: this.form.email.value,
        password: this.form.password.value
      })
        .then(() => {
          this.$toast.open({
            message: this.$i18n.t('login.toast_success'),
            type: 'success'
          })

          if (this.$route.query.redirectUrl) {
            this.$router.push({ path: this.$route.query.redirectUrl })
          } else {
            this.$router.push({ name: 'internal' })
          }
        })
        .catch((err) => {
          let validation = {
            404: 'globals.toast.not_foud'
          }
          if (err && err.data && err.data.content) {
            if (err.data.content.includes('account email not confirmed')) {
              validation.custom = 'login.toast_account_not_confirmed'
            } else if (err.data.content.includes('user already logged')) {
              validation.custom = 'login.toast_account_already_logged'
            } else if (err.data.content.includes('invalid username or password')) {
              validation.custom = 'login.toast_username_password_invalid'
            }
          }
          this.handleError(err, validation)
        })
        .finally(() => {
          this.isLoading = false
        })
    },
    goToSignUp () {
      this.$router.push({ name: 'sign-up' })
    }
  }
}
