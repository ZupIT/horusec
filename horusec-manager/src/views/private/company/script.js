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

import Footer from '@/components/footer/index.vue'
import Moment from 'moment'
import { mapActions, mapMutations } from 'vuex'
import FormValidations from '@/mixins/form-validations'

export default {
  mixins: [
    FormValidations
  ],
  components: {
    Footer
  },
  data: () => ({
    search: '',
    isSearch: false,
    form: {
      isOpen: false,
      type: '',
      valid: false,
      companyId: {
        value: ''
      },
      companyName: {
        value: '',
        rules: []
      }
    },
    isLoading: true,
    moment: Moment,
    companies: []
  }),
  computed: {
    searchedCompany () {
      if (this.search) {
        return this.companies.filter(company => company.name.toLowerCase().includes(this.search)).sort((a, b) => a.name.localeCompare(b.name))
      }
      return this.companies.sort((a, b) => a.name.localeCompare(b.name))
    }
  },
  mounted () {
    this.form.companyName.rules = [
      v => this.validateFieldRequired(v)
    ]

    this.getAllCompany()
  },
  methods: {
    ...mapActions([
      'actionGetOneCompany',
      'actionGetAllCompany',
      'actionCreateCompany',
      'actionUpdateCompany',
      'actionDeleteCompany',
      'actionLogout'
    ]),
    ...mapMutations([
      'SET_COMPANY_SELECTED'
    ]),
    selectCompay (company) {
      this.isLoading = true
      this.actionGetOneCompany(company.companyID)
        .then(() => {
          this.$router.push({ name: 'dashboard', query: { companyId: company.companyID } })
        })
        .catch((err) => this.handleError(err))
        .finally(() => this.isLoading = false)
    },
    logout () {
      this.isLoading = true

      this.actionLogout()
        .finally(() => this.isLoading = false)
    },
    getAllCompany () {
      this.actionGetAllCompany()
        .then((res) => {
          this.companies = res.data.content
          this.reset()
        })
        .catch((err) => this.handleError(err, {
          404: 'globals.toast.not_foud'
        }))
        .finally(() => this.isLoading = false)
    },
    createCompany () {
      this.isLoading = true

      this.actionCreateCompany(this.form.companyName.value)
        .then(() => {
          this.$toast.open({
            message: this.$i18n.t('company.toast.company_created'),
            type: 'success'
          })
          this.getAllCompany()
        })
        .catch((err) => {
          this.isLoading = false
          this.handleError(err, {})
        })
    },
    editCompany () {
      this.isLoading = true

      this.actionUpdateCompany({
        id: this.form.companyId.value,
        name: this.form.companyName.value
      })
        .then(() => {
          this.$toast.open({
            message: this.$i18n.t('company.toast.company_updated'),
            type: 'success'
          })
          this.getAllCompany()
        })
        .catch((err) => {
          this.isLoading = false
          this.handleError(err, {
            403: 'globals.toast.user_without_permission'
          })
        })
    },
    deleteCompany () {
      this.isLoading = true

      this.actionDeleteCompany(this.form.companyId.value)
        .then(() => {
          this.$toast.open({
            message: this.$i18n.t('company.toast.company_deleted'),
            type: 'success'
          })
          this.getAllCompany()
        })
        .catch((err) => {
          this.isLoading = false
          this.handleError(err, {
            403: 'globals.toast.user_without_permission'
          })
        })
    },
    callActionInCompany (action, company) {
      switch (action) {
        case this.$i18n.t('company.actions.select'):
          return this.selectCompay(company)
        case this.$i18n.t('company.actions.edit'):
          return this.openModalToEdit(company)
        case this.$i18n.t('company.actions.delete'):
          return this.openModalToDelete(company)
      }
    },
    openModalToCreate () {
      this.form.isOpen = true
      this.form.type = 'create'
    },
    openModalToEdit (company) {
      this.form.isOpen = true
      this.form.type = 'edit'
      this.form.companyId.value = company.companyID
      this.form.companyName.value = company.name
    },
    openModalToDelete (company) {
      this.form.isOpen = true
      this.form.type = 'delete'
      this.form.companyId.value = company.companyID
      this.form.companyName.value = company.name
    },
    reset () {
      this.isLoading = false
      this.isSearch = false
      if (this.$refs.form) {
        this.$refs.form.reset()
      }
      this.form.isOpen = false
      this.form.type = ''
      this.form.companyId.value = ''
    }
  }
}
