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

export default {
  mixins: [
    FormValidations
  ],
  data: () => ({
    table: {
      headers: [],
      content: []
    },
    isHelpPermission: false,
    form: {
      isOpen: false,
      type: '',
      valid: false,
      accountId: {
        value: ''
      },
      userEmail: {
        value: '',
        rules: []
      },
      userRole: {
        value: '',
        rules: []
      }
    },
    isLoading: false,
    search: ''
  }),
  mounted () {
    this.form.userEmail.rules = [
      v => this.validateFieldRequired(v),
      v => this.validateEmailInvalid(v)
    ]
    this.form.userRole.rules = [
      v => this.validateFieldRequired(v)
    ]
    this.getAllUsers()
  },
  computed: {
    ...mapGetters([
      'getterUserLogged',
      'getterSelectedCompany'
    ]),
    tableHeaders () {
      this.formatI18NTableContent()
      return [
        { text: this.$i18n.t('user.table.header_username'), value: 'username' },
        { text: this.$i18n.t('user.table.header_email'), value: 'email' },
        { text: this.$i18n.t('user.table.header_role'), value: 'roleLabel' },
        { text: this.$i18n.t('globals.table.header_action'), value: 'actions', sortable: false, width: '130px' }
      ]
    },
    roles () {
      this.formatI18NTableContent()
      return [
        { name: this.$i18n.t('user.table.item_role_admin'), value: 'admin' },
        { name: this.$i18n.t('user.table.item_role_member'), value: 'member' }
      ]
    },
    searchTableContent () {
      if (this.table && this.table.content) {
        if (this.search) {
          return this.table.content.filter(item => item.email.toLowerCase().includes(this.search)).sort((a, b) => a.username.localeCompare(b.username))
        }
        return this.table.content.sort((a, b) => a.username.localeCompare(b.username))
      }

      return []
    }
  },
  methods: {
    ...mapActions([
      'actionGetAllUsersInCompany',
      'actionCreateUserInCompany',
      'actionEditUserInCompany',
      'actionRemoveUserInCompany'
    ]),
    isToDisableAction (email) {
      return (
        this.getterUserLogged.role === 'member'
        || this.getterUserLogged.email === email
      )
    },
    getAllUsers () {
      this.isLoading = true
      this.table = {
        headers: [],
        content: []
      }

      return this.actionGetAllUsersInCompany(this.getterSelectedCompany.companyID)
        .then((result) => {
          this.table.content = result.data.content
          this.formatI18NTableContent()
        })
        .catch((err) => this.handleError(err, {
          403: 'globals.toast.user_without_permission'
        }))
        .finally(() => this.isLoading = false)
    },
    formatI18NTableContent () {
      this.table.content.forEach((element) => {
        if (element.role === 'admin') {
          element.roleLabel = this.$i18n.t('user.table.item_role_admin')
        } else if (element.role === 'member') {
          element.roleLabel = this.$i18n.t('user.table.item_role_member')
        }
      })
    },
    setEditItem (item) {
      this.form.isOpen = true
      this.form.type = 'edit'
      this.form.accountId.value = item.accountID
      this.form.userEmail.value = item.email
      this.form.userRole.value = item.role
      setTimeout(() => {
        this.form.valid = true
      }, 300)
    },
    setDeleteItem (item) {
      this.form.isOpen = true
      this.form.type = 'delete'
      this.form.accountId.value = item.accountID
      this.form.userEmail.value = item.email
      this.form.userRole.value = item.role
      setTimeout(() => {
        this.form.valid = true
      }, 300)
    },
    setCreateItem () {
      this.form.isOpen = true
      this.form.type = 'create'
    },
    async createUser () {
      this.isLoading = false
      const params = {
        email: this.form.userEmail.value,
        role: this.form.userRole.value,
        companyId: this.getterSelectedCompany.companyID
      }

      await this.actionCreateUserInCompany(params)
        .then(async () => {
          await this.getAllUsers()

          this.$toast.open({
            message: this.$i18n.t('user.toast.user_created'),
            type: 'success'
          })

          this.reset()
        })
        .catch((err) => this.handleError(err, {
          409: 'user.toast.user_already_exist',
          404: 'user.toast.user_not_found',
          403: 'globals.toast.user_without_permission'
        }))

      this.isLoading = false
    },
    async editUser () {
      this.isLoading = false
      const params = {
        accountId: this.form.accountId.value,
        role: this.form.userRole.value,
        companyId: this.getterSelectedCompany.companyID
      }

      await this.actionEditUserInCompany(params)
        .then(async () => {
          await this.getAllUsers()

          this.$toast.open({
            message: this.$i18n.t('user.toast.user_updated'),
            type: 'success'
          })

          this.reset()
        })
        .catch((err) => this.handleError(err, {
          403: 'globals.toast.user_without_permission'
        }))

      this.isLoading = false
    },
    async deleteUser () {
      this.isLoading = false
      const params = {
        accountId: this.form.accountId.value,
        companyId: this.getterSelectedCompany.companyID
      }

      await this.actionRemoveUserInCompany(params)
        .then(async () => {
          await this.getAllUsers()

          this.$toast.open({
            message: this.$i18n.t('user.toast.user_deleted'),
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
      this.isHelpPermission = false
      this.isLoading = false
      this.form = {
        isOpen: false,
        type: '',
        valid: false,
        accountId: {
          value: ''
        },
        userEmail: {
          value: '',
          rules: [
            v => this.validateFieldRequired(v),
            v => this.validateEmailInvalid(v)
          ]
        },
        userRole: {
          value: '',
          rules: [
            v => this.validateFieldRequired(v)
          ]
        }
      }
    }
  }
}
