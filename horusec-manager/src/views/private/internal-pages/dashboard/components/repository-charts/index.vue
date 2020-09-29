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
  <div
    class="dashboard-content-repository"
    :class="{ isLoadingCharts }"
  >
    <v-select
      v-model="repositoryIdSelected"
      :label="$i18n.t('dashboard.repository.label_select')"
      :placeholder="$i18n.t('dashboard.repository.placeholder_select')"
      :disabled="isLoading || isLoadingCharts"
      :items="repositories"
      item-text="name"
      item-value="repositoryID"
      style="width: 100%;"
      @change="updateCharts()"
    />

    <GenericsCharts
      v-if="!isLoading && repositoryIdSelected && repositoryIdSelected.length"
      :disable-chart-total-repositories="true"
      :disable-chart-severity-by-repositories="true"
    />
  </div>
</template>

<style lang="scss">
  @import './style.scss';
</style>

<script src="./script.js" />
