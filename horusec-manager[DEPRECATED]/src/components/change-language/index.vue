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
  <section
    class="change-language"
  >
    <v-select
      v-model="$i18n.locale"
      class="theme--dark"
      :items="items"
      :label="$i18n.t('globals.change_i18n.label')"
      item-text="name"
      item-value="name"
      dense
      solo
      @change="setSeletedLanguage()"
    >
      <template v-slot:item="{ item }">
        <img
          :src="item.image"
          width="30px"
          height="15px"
        >

        <span style="margin-left: 10px;">
          {{ item.name }}
        </span>
      </template>
    </v-select>
  </section>
</template>

<script src="./script.js" />

<style lang="scss">
  @import './style.scss';
</style>
