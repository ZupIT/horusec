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
import VueI18n from 'vue-i18n'
import LangPtBr from '@/assets/i18n/pt-br.json'
import LangEn from '@/assets/i18n/en.json'

Vue.use(VueI18n)

export default new VueI18n({
  locale: 'pt-BR',
  messages: {
    'pt-BR': LangPtBr,
    'en-US': LangEn
  }
})
