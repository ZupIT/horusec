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
    id="generics-charts"
    ref="generics-charts"
    class="charts generics-charts"
  >
    <v-row>
      <v-col
        cols="12"
        xl="3"
        lg="3"
        md="3"
        sm="12"
        xs="12"
      >
        <ChartTotalDevelopers />
      </v-col>

      <v-col
        v-if="!disableChartTotalRepositories"
        cols="12"
        xl="3"
        lg="3"
        md="3"
        sm="12"
        xs="12"
      >
        <ChartTotalRepositories />
      </v-col>

      <v-col
        cols="12"
        :xl="!disableChartTotalRepositories ? 6 : 9"
        :lg="!disableChartTotalRepositories ? 6 : 9"
        :md="!disableChartTotalRepositories ? 6 : 9"
        sm="12"
        xs="12"
      >
        <ChartAllSeverity />
      </v-col>
    </v-row>

    <v-row>
      <v-col
        cols="12"
        :xl="!disableChartSeverityByRepositories ? '4' : '6'"
        :lg="!disableChartSeverityByRepositories ? '4' : '6'"
        md="12"
        sm="12"
        xs="12"
      >
        <ChartSeverityByDeveloper />
      </v-col>

      <v-col
        cols="12"
        :xl="!disableChartSeverityByRepositories ? '4' : '6'"
        :lg="!disableChartSeverityByRepositories ? '4' : '6'"
        md="12"
        sm="12"
        xs="12"
      >
        <ChartSeverityByLanguage />
      </v-col>

      <v-col
        cols="12"
        xl="4"
        lg="4"
        md="12"
        sm="12"
        xs="12"
      >
        <ChartSeverityByRepository
          v-if="!disableChartSeverityByRepositories"
        />
      </v-col>
    </v-row>

    <v-row>
      <v-col cols="12">
        <ChartSeverityByTime />
      </v-col>
    </v-row>

    <v-row>
      <v-col cols="12">
        <ChartSeverityDetailsTable />
      </v-col>
    </v-row>
  </section>
</template>

<script src="./script.js" />
