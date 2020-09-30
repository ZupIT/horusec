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
    :loading="getterLoadingChartSeverityDetails"
    :disabled="!startDate || !endDate"
    elevation="10"
    class="chart "
  >
    <v-card-title>
      {{ $i18n.t('dashboard.charts.title_vulnerabilities_details_table') }}
    </v-card-title>

    <v-container
      id="chart-severity-details-table"
      key="chart-severity-details-table"
      style="max-width: 100%;"
    >
      <v-data-table
        :headers="tableHeader"
        :items="data"
        :items-per-page="size"
        :server-items-length="totalItems"
        :page="page"
        :height="400"
        :footer-props="{'items-per-page-options': [20, 40, 80, 200]}"
        @update:items-per-page="(event) => { size = event; getDataChart() }"
        @update:page="(event) => { page = event; getDataChart() }"
      />
    </v-container>
  </v-card>
</template>

<script src="./script.js" />
