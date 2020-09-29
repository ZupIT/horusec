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
  <section class="container-not-found gradient-container">
    <v-card elevation="10">
      <h1>{{ $i18n.t('not_found.title') }}</h1>

      <h3>{{ $i18n.t('not_found.message') }}</h3>

      <router-link :to="{ 'name': 'auth' }">
        {{ $i18n.t('not_found.btn_home') }}
      </router-link>
    </v-card>

    <Footer />
  </section>
</template>

<script src="./script.js"></script>

<style lang="scss">
  @import './style.scss';
</style>
