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
    validateFieldRequired (v) {
      if (v && v.length > 0) {
        return true
      }
      return this.$i18n.t('globals.form.rules.field_required')
    },
    validateEmailInvalid (v) {
      const regexEmail = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,3}$/
      if (!regexEmail.test(v)) {
        return this.$i18n.t('globals.form.rules.email_invalid')
      }
      return true
    },
    validateCodeInvalid (v) {
      if (!/^.{6,6}$/.test(v)) {
        return this.$i18n.t('recovery_password.form.code_invalid')
      }
      return true
    },
    validatePasswordInvalid (v) {
      let msg = ''
      if (!/^.{8,}$/.test(v)) {
        msg += this.$i18n.t('globals.form.rules.password_invalid.min_characters')
      }
      if (!/[A-Z]/.test(v)) {
        msg += this.$i18n.t('globals.form.rules.password_invalid.min_capital_character')
      }
      if (!/[a-z]/.test(v)) {
        msg += this.$i18n.t('globals.form.rules.password_invalid.min_lower_character')
      }
      if (!/[!@#$&*-._]/.test(v)) {
        msg += this.$i18n.t('globals.form.rules.password_invalid.min_special_character')
      }
      if (!/[0-9]/.test(v)) {
        msg += this.$i18n.t('globals.form.rules.password_invalid.min_number_character')
      }
      if (msg.length > 0) {
        return msg
      }
      return true
    },
    validateConfirmPasswordEqualsPassword (v, pass) {
      if (v === pass) {
        return true
      }
      return this.$i18n.t('recovery_password.form.passwords_not_equals')
    }
  }
}
