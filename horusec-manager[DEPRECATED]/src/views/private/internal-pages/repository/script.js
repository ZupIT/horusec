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

import { mapGetters, mapActions } from 'vuex'
import FormValidations from '@/mixins/form-validations'
import UsersRepository from './components/users-repository/index.vue'
import TokensRepository from './components/tokens-repository/index.vue'

export default {
  mixins: [
    FormValidations
  ],
  components: {
    UsersRepository,
    TokensRepository
  },
  data: () => ({
    table: {
      headers: [],
      content: []
    },
    repositorySelected: {
      isOpen: false,
      type: '',
      value: {}
    },
    form: {
      isOpen: false,
      type: '',
      valid: false,
      repositoryId: {
        value: ''
      },
      name: {
        value: '',
        rules: []
      },
      description: {
        value: '',
        rules: []
      }
    },
    isLoading: false,
    search: ''
  }),
  mounted () {
    this.form.name.rules = [
      v => this.validateFieldRequired(v)
    ]
    this.getAllRepositories()
  },
  computed: {
    ...mapGetters([
      'getterUserLogged',
      'getterSelectedCompany'
    ]),
    tableHeaders () {
      return [
        { text: this.$i18n.t('repository.table.header_name'), value: 'name' },
        { text: this.$i18n.t('repository.table.header_description'), value: 'description' },
        { text: this.$i18n.t('globals.table.header_action'), value: 'actions', sortable: false, width: '260px' }
      ]
    },
    searchTableContent () {
      if (this.table && this.table.content) {
        if (this.search) {
          return this.table.content.filter(item => item.name.toLowerCase().includes(this.search)).sort((a, b) => a.name.localeCompare(b.name))
        }
        return this.table.content.sort((a, b) => a.name.localeCompare(b.name))
      }

      return []
    }
  },
  methods: {
    ...mapActions([
      'actionGetAllRepository',
      'actionCreateRepository',
      'actionEditRepository',
      'actionRemoveRepository'
    ]),
    setEditUsers (item) {
      this.repositorySelected = {
        isOpen: true,
        type: 'users',
        value: item
      }
    },
    setEditTokens (item) {
      this.repositorySelected = {
        isOpen: true,
        type: 'tokens',
        value: item
      }
    },
    getAllRepositories () {
      this.isLoading = true
      this.table = {
        headers: [],
        content: []
      }

      return this.actionGetAllRepository(this.getterSelectedCompany.companyID)
        .then((result) => {
          this.table.content = result.data.content
        })
        .catch((err) => this.handleError(err, {
          403: 'globals.toast.user_without_permission'
        }))
        .finally(() => this.isLoading = false)
    },
    setEditItem (item) {
      this.form.isOpen = true
      this.form.type = 'edit'
      this.form.repositoryId.value = item.repositoryID
      this.form.name.value = item.name
      this.form.description.value = item.description
      setTimeout(() => {
        this.form.valid = true
      }, 300)
    },
    setDeleteItem (item) {
      this.form.isOpen = true
      this.form.type = 'delete'
      this.form.repositoryId.value = item.repositoryID
      this.form.name.value = item.name
      this.form.description.value = item.description
      setTimeout(() => {
        this.form.valid = true
      }, 300)
    },
    setCreateItem () {
      this.form.isOpen = true
      this.form.type = 'create'
    },
    async createRepository () {
      this.isLoading = false
      const params = {
        name: this.form.name.value,
        description: this.form.description.value,
        companyId: this.getterSelectedCompany.companyID
      }

      await this.actionCreateRepository(params)
        .then(async () => {
          await this.getAllRepositories()

          this.$toast.open({
            message: this.$i18n.t('repository.toast.repository_created'),
            type: 'success'
          })

          this.reset()
        })
        .catch((err) => this.handleError(err, {
          403: 'globals.toast.user_without_permission'
        }))

      this.isLoading = false
    },
    async editRepository () {
      this.isLoading = false
      const params = {
        repositoryId: this.form.repositoryId.value,
        name: this.form.name.value,
        description: this.form.description.value,
        companyId: this.getterSelectedCompany.companyID
      }

      await this.actionEditRepository(params)
        .then(async () => {
          await this.getAllRepositories()

          this.$toast.open({
            message: this.$i18n.t('repository.toast.repository_updated'),
            type: 'success'
          })

          this.reset()
        })
        .catch((err) => this.handleError(err, {
          403: 'globals.toast.user_without_permission'
        }))

      this.isLoading = false
    },
    async deleteRepository () {
      this.isLoading = false
      const params = {
        repositoryId: this.form.repositoryId.value,
        companyId: this.getterSelectedCompany.companyID
      }

      await this.actionRemoveRepository(params)
        .then(async () => {
          await this.getAllRepositories()

          this.$toast.open({
            message: this.$i18n.t('repository.toast.repository_deleted'),
            type: 'success'
          })

          this.reset()
        })
        .catch((err) => this.handleError(err, {
          403: 'globals.toast.user_without_permission'
        }))

      this.isLoading = false
    },
    reset () {
      this.isLoading = false
      this.form = {
        isOpen: false,
        type: '',
        valid: false,
        repositoryId: {
          value: ''
        },
        name: {
          value: '',
          rules: [
            v => this.validateFieldRequired(v)
          ]
        },
        description: {
          value: '',
          rules: []
        }
      }
      this.repositorySelected = {
        isOpen: false,
        type: '',
        value: {}
      }
    }
  }
}
