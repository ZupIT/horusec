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

export default {
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
    isLoading: false,
    isHelpPermission: false,
    search: ''
  }),
  computed: {
    ...mapGetters([
      'getterUserLogged',
      'getterSelectedCompany'
    ]),
    tableHeaders () {
      this.getAllUsers()

      return [
        { text: this.$i18n.t('user.table.header_username'), value: 'username' },
        { text: this.$i18n.t('user.table.header_email'), value: 'email' },
        { text: this.$i18n.t('user.table.header_role'), value: 'roleLabel', sortable: false, width: '200px' }
      ]
    },
    roles () {
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
      'actionGetAllUsersInRepository',
      'actionCreateUserInRepository',
      'actionDeleteUserInRepository',
      'actionUpdateUserInRepository'
    ]),
    async getAllUsers () {
      this.isLoading = true
      this.table = {
        content: []
      }
      const params = {
        companyId: this.getterSelectedCompany.companyID,
        repositoryId: this.repositoryId
      }
      let users = []
      await this.actionGetAllUsersInCompany(params.companyId)
        .then(async (result) => {
          users = result.data.content

          users.forEach((element) => {
            if (element.role === 'admin') {
              element.roleLabel = this.$i18n.t('user.table.item_role_admin')
            } else if (element.role === 'member') {
              element.roleLabel = this.$i18n.t('user.table.item_role_member')
            }
            element.selected = false
          })

          await this.actionGetAllUsersInRepository(params)
            .then(async (result) => {
              if (result.data.content && result.data.content.length) {
                users.forEach((userCompany) => {
                  result.data.content.forEach((userRepository) => {
                    if (userCompany.accountID === userRepository.accountID) {
                      userCompany.selected = true
                      if (userRepository.role === 'admin') {
                        userCompany.roleLabel = this.$i18n.t('user.table.item_role_admin')
                        userCompany.role = 'admin'
                      } else if (userRepository.role === 'member') {
                        userCompany.roleLabel = this.$i18n.t('user.table.item_role_member')
                        userCompany.role = 'member'
                      }
                    }
                  })
                })
              }

              this.table.content = users
            })
            .catch((err) => this.handleError(err, {
              403: 'repository.user_without_permission'
            }))
        })
        .catch((err) => this.handleError(err, {}))

      this.isLoading = false
    },
    async addOrRemoveUser (user) {
      this.isLoading = true
      if (user.selected) {
        await this.addUserInRepository(user)
      } else {
        await this.removeUserInRepository(user)
      }
      this.reset()
    },
    async addUserInRepository (user) {
      const params = {
        companyId: this.getterSelectedCompany.companyID,
        repositoryId: this.repositoryId,
        accountId: user.accountID,
        email: user.email,
        role: user.role
      }
      await this.actionCreateUserInRepository(params)
        .then(() => {
          this.$toast.open({
            message: this.$i18n.t('repository.user.toast.user_created'),
            type: 'success'
          })
        })
        .catch((err) => this.handleError(err))
    },
    async removeUserInRepository (user) {
      const params = {
        companyId: this.getterSelectedCompany.companyID,
        repositoryId: this.repositoryId,
        accountId: user.accountID
      }
      this.actionDeleteUserInRepository(params)
        .then(() => {
          this.$toast.open({
            message: this.$i18n.t('repository.user.toast.user_deleted'),
            type: 'success'
          })
          this.reset()
        })
        .catch((err) => this.handleError(err))
    },
    async updateUser (event, user) {
      const params = {
        companyId: this.getterSelectedCompany.companyID,
        repositoryId: this.repositoryId,
        accountId: user.accountID,
        email: user.email,
        role: event
      }
      await this.actionUpdateUserInRepository(params)
        .then(() => {
          this.$toast.open({
            message: this.$i18n.t('repository.user.toast.user_updated'),
            type: 'success'
          })
        })
        .catch((err) => this.handleError(err))
    },
    reset () {
      this.isHelpPermission = false
      this.getAllUsers()
    }
  }
}
