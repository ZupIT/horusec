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

import {mapActions, mapGetters} from 'vuex'
import FormValidations from '@/mixins/form-validations'
import moment from 'moment'

export default {
  mixins: [
    FormValidations
  ],
  props: {
    repositoryId: {
      required: true,
      type: String
    }
  },
  data: () => ({
    table: {
      content: []
    },
    form: {
      isOpen: false,
      type: '',
      valid: false,
      description: {
        value: '',
        rules: []
      },
      token: {
        value: ''
      },
      tokenId: {
        value: ''
      }
    },
    isLoading: false
  }),
  computed: {
    ...mapGetters([
      'getterSelectedCompany',
      'getterLanguage'
    ]),
    tableHeaders () {
      this.getAllTokens()

      return [
        { text: this.$i18n.t('repository.tokens.table.header_token'), value: 'token' },
        { text: this.$i18n.t('repository.tokens.table.header_description'), value: 'description' },
        { text: this.$i18n.t('repository.tokens.table.header_expiresAt'), value: 'expiresAt' },
        { text: this.$i18n.t('globals.table.header_action'), value: 'actions', sortable: false, width: '65px' }
      ]
    }
  },
  mounted () {
    this.form.description.rules = [
      v => this.validateFieldRequired(v)
    ]
  },
  methods: {
    ...mapActions([
      'actionGetAllTokensInRepository',
      'actionCreateTokensInRepository',
      'actionDeleteTokensInRepository'
    ]),
    async getAllTokens () {
      this.isLoading = true
      this.table = {
        content: []
      }
      const params = {
        repositoryId: this.repositoryId,
        companyId: this.getterSelectedCompany.companyID
      }

      await this.actionGetAllTokensInRepository(params)
        .then((result) => {
          if (result.data.content) {
            this.table.content = result.data.content

            this.table.content.forEach(element => {
              element.token = `***************${element.suffixValue}`
              if (element.expiresAt) {
                if (this.getterLanguage === 'pt-BR') {
                  element.expiresAt = moment(element.expiresAt).format('DD/MM/YYYY')
                } else {
                  element.expiresAt = moment(element.expiresAt).format('YYYY-MM-DD')
                }
              }
            })
          }
        })
        .catch((err) => this.handleError(err))

      this.isLoading = false
    },
    setCreateItem () {
      this.form.isOpen = true
      this.form.type = 'create'
    },
    setDeleteItem (item) {
      this.form.isOpen = true
      this.form.type = 'delete'
      this.form.tokenId.value = item.tokenID
      this.form.description.value = item.description
    },
    async createToken () {
      this.isLoading = true

      const params = {
        repositoryId: this.repositoryId,
        companyId: this.getterSelectedCompany.companyID,
        description: this.form.description.value
      }

      await this.actionCreateTokensInRepository(params)
        .then((result) => {
          this.$toast.open({
            message: this.$i18n.t('repository.tokens.toast.token_created'),
            type: 'success'
          })

          this.form.type = 'create_success'
          this.form.token.value = result.data.content
        })
        .catch((err) => this.handleError(err))

      this.isLoading = false
    },
    async deleteToken () {
      this.isLoading = true

      const params = {
        repositoryId: this.repositoryId,
        companyId: this.getterSelectedCompany.companyID,
        tokenId: this.form.tokenId.value
      }

      await this.actionDeleteTokensInRepository(params)
        .then(() => {
          this.$toast.open({
            message: this.$i18n.t('repository.tokens.toast.token_deleted'),
            type: 'success'
          })

          this.reset()
        })
        .catch((err) => this.handleError(err))

      this.isLoading = false
    },
    reset () {
      this.isLoading = false
      this.form = {
        isOpen: false,
        valid: false,
        description: {
          value: '',
          rules: [
            v => this.validateFieldRequired(v)
          ]
        },
        token: {
          value: ''
        },
        tokenId: {
          value: ''
        }
      }
    }
  }
}
