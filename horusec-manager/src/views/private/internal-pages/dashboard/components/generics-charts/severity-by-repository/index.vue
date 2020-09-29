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
  <v-card
    :loading="getterLoadingChartSeverityByRepository"
    elevation="10"
    class="chart severity-by-repository"
  >
    <v-card-title>
      {{ $i18n.t('dashboard.charts.title_vulnerabilities_by_repository') }}
    </v-card-title>

    <v-container
      id="chart-severity-by-repository"
      key="chart-severity-by-repository"
      style="height: 300px;"
    >
      <span
        v-if="getterLoadingChartSeverityByRepository || (!chart.data || (chart.data && !chart.data.length))"
        class="not-found-chart-data"
      >
        {{ $i18n.t('globals.not_found') }}
      </span>

      <Graph
        v-if="!getterLoadingChartSeverityByRepository && chart && chart.data && chart.data.length"
        :data-and-labels="chart"
      />
    </v-container>
  </v-card>
</template>

<script src="./script.js" />
