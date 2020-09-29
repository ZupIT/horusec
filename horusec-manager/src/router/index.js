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

import Vue from 'vue'
import VueRouter from 'vue-router'

Vue.use(VueRouter)

const routes = [
  {
    path: '*',
    redirect: '/not-found'
  },
  {
    path: '/',
    redirect: '/auth'
  },
  {
    path: '/not-found',
    name: 'not-found',
    component: () => import('../views/public/not-found/index.vue')
  },
  {
    path: '/auth',
    name: 'auth',
    redirect: '/auth/login',
    component: () => import('../views/public/auth/index.vue'),
    beforeEnter: (to, from, next) => {
      const token = Vue.prototype.$globalStore.getters.getterAccessToken
      if (token && token.length > 0) {
        next('/internal')
      } else {
        next()
      }
    },
    children: [
      {
        path: '/auth/login',
        name: 'login',
        component: () => import('../views/public/auth/login/index.vue')
      },
      {
        path: '/auth/recovery-password',
        name: 'recovery-password',
        redirect: '/auth/recovery-password/send-email'
      },
      {
        path: '/auth/recovery-password/send-email',
        name: 'recovery-password-send-email',
        component: () => import('../views/public/auth/recovery-pass/send-email/index.vue')
      },
      {
        path: '/auth/recovery-password/send-code',
        name: 'recovery-password-send-code',
        component: () => import('../views/public/auth/recovery-pass/send-code/index.vue'),
        beforeEnter: (to, from, next) => {
          if (to.query && to.query.email && to.query.email.length > 0) {
            next()
          } else {
            next({ name: 'recovery-password-send-email' })
          }
        }
      },
      {
        path: '/auth/recovery-password/change-password',
        name: 'recovery-password-change-password',
        component: () => import('../views/public/auth/recovery-pass/change-password/index.vue'),
        beforeEnter: (to, from, next) => {
          if (to.query && to.query.token && to.query.token.length > 0) {
            next()
          } else {
            next({ name: 'recovery-password-send-email' })
          }
        }
      },
      {
        path: '/auth/sign-up',
        name: 'sign-up',
        component: () => import('../views/public/auth/sign-up/index.vue')
      }
    ]
  },
  {
    path: '/internal',
    name: 'internal',
    redirect: '/internal/company',
    component: () => import('../views/private/index.vue'),
    beforeEnter: (to, from, next) => {
      const token = Vue.prototype.$globalStore.getters.getterAccessToken
      if (token && token.length > 0) {
        next()
      } else {
        next({ name: 'login', query: { redirectUrl: to.fullPath } })
      }
    },
    children: [
      {
        path: '/internal/company',
        name: 'company',
        component: () => import('../views/private/company/index.vue')
      },
      {
        path: '/internal/pages',
        redirect: '/internal/pages/dashboard',
        name: 'internal-pages',
        component: () => import('../views/private/internal-pages/index.vue'),
        beforeEnter: async (to, from, next) => {
          if (to.query.companyId) {
            const company = Vue.prototype.$globalStore.getters.getterSelectedCompany
            if (company && company.companyID) {
              next({ query: { companyId: company.companyID } })
            } else {
              Vue.prototype.$globalStore.dispatch('actionGetOneCompany', to.query.companyId)
                .then(() => {
                  next()
                })
                .catch(() => {
                  Vue.prototype.$globalStore.commit('SET_COMPANY_SELECTED', {})
                  next({ name: 'company' })
                })
            }
          } else {
            Vue.prototype.$globalStore.commit('SET_COMPANY_SELECTED', {})
            next({ name: 'company' })
          }
        },
        children: [
          {
            path: '/internal/pages/dashboard',
            name: 'dashboard',
            component: () => import('../views/private/internal-pages/dashboard/index.vue')
          },
          {
            path: '/internal/pages/repository',
            name: 'repository',
            component: () => import('../views/private/internal-pages/repository/index.vue')
          },
          {
            path: '/internal/pages/user',
            name: 'user',
            component: () => import('../views/private/internal-pages/user/index.vue')
          }
        ]
      }
    ]
  }
]

const router = new VueRouter({
  routes,
  mode: 'history'
})

export default router
