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
import axios from 'axios'
import VueToast from 'vue-toast-notification'
import App from './app.vue'
import router from './router'
import store from './store'
import vuetify from './plugins/vuetify'
import i18n from './plugins/vue-i18n'
import handleToastError from './mixins/handle-toast-error'
import 'vue-toast-notification/dist/theme-default.css'

Vue.config.productionTip = false

Vue.prototype.$eventBus = new Vue()
Vue.prototype.$globalStore = store
Vue.prototype.$globalRouter = router

Vue.use(VueToast)
Vue.use(axios)

Vue.mixin(handleToastError)

new Vue({
  router,
  store,
  vuetify,
  i18n,
  render: h => h(App)
}).$mount('#app')
