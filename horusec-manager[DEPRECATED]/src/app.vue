<!--
 Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

<template>
  <v-app>
    <v-main>
      <router-view />
    </v-main>
  </v-app>
</template>

<style lang="scss">
.gradient-container { display: flex; justify-content: center; align-items: center; width: 100%; height: 100%; margin: 0; padding: 30px; background: linear-gradient(110deg, rgba(5, 61, 102, 1) 0%, rgba(229, 126, 6, 1) 50%, rgba(138, 186, 64, 1) 100%); position: relative; }

.notices .toast { opacity: 1 !important; }
</style>

<script>
import { mapMutations, mapGetters } from 'vuex'

export default {
  name: 'App',
  computed: {
    ...mapGetters([
      'getterLanguage'
    ])
  },
  mounted () {
    if (!this.getterLanguage) {
      this.SET_LANGUAGE('pt-BR')
    }
    this.$i18n.locale = this.getterLanguage
  },
  methods: {
    ...mapMutations([
      'SET_LANGUAGE'
    ])
  }
}
</script>
