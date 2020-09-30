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

import { mapActions, mapMutations, mapGetters } from 'vuex'
import Package from '../../../package.json'
import Footer from '@/components/footer/index.vue'
import HorusecLogo from '@/components/horusec-logo/index.vue'

export default {
  components: {
    Footer,
    HorusecLogo
  },
  data () {
    return {
      version: Package.version,
      navigationDrawerIsOpen: false,
      isLogout: false,
      navigationDrawerItems: [
        { title: 'internal.menu.back_to_companies', icon: 'mdi-domain', type: 'company' },
        { title: 'internal.menu.dashboard', icon: 'mdi-view-dashboard', type: 'dashboard' },
        { title: 'internal.menu.repositories', icon: 'mdi-source-repository', type: 'repository' },
        { title: 'internal.menu.users', icon: 'mdi-account-group', type: 'user' }
      ]
    }
  },
  computed: {
    ...mapGetters([
      'getterSelectedCompany'
    ]),
    getTitleByRoute () {
      if (this.$route.name === 'dashboard') {
        return 'dashboard.title'
      }
      if (this.$route.name === 'repository') {
        return 'repository.title'
      }
      if (this.$route.name === 'user') {
        return 'user.title'
      }
      return ''
    },
    getDescriptionByRoute () {
      if (this.$route.name === 'dashboard') {
        return 'dashboard.description'
      }
      if (this.$route.name === 'repository') {
        return 'repository.description'
      }
      if (this.$route.name === 'user') {
        return 'user.description'
      }
      return ''
    }
  },
  watch: {
    $route () {
      this.navigationDrawerIsOpen = false
    }
  },
  methods: {
    ...mapActions([
      'actionLogout'
    ]),
    ...mapMutations([
      'SET_COMPANY_SELECTED'
    ]),
    logout () {
      this.isLogout = true
      this.actionLogout()
    },
    factoryMenu (type) {
      switch(type) {
        case 'company':
          this.SET_COMPANY_SELECTED({})
          this.$router.push({ name: 'internal' })
          break
        case 'dashboard':
          if (this.$route.name !== 'dashboard') {
            this.$router.push({ name: 'dashboard', query: this.$route.query })
          }
          break
        case 'repository':
          if (this.$route.name !== 'repository') {
            this.$router.push({ name: 'repository', query: this.$route.query })
          }
          break
        case 'user':
          if (this.$route.name !== 'user') {
            this.$router.push({ name: 'user', query: this.$route.query })
          }
          break
      }
    }
  }
}
