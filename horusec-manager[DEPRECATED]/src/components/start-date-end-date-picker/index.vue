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
  <v-container>
    <v-form
      ref="form"
      v-model="form.valid"
      @submit.prevent
    >
      <v-container>
        <v-row
          align="center"
          justify="center"
        >
          <v-col
            v-if="hasAction"
            cols="12"
            xl="1"
            lg="1"
            md="1"
            sm="12"
            xs="12"
          />

          <v-col
            cols="12"
            :xl="hasAction ? '5' : '6'"
            :lg="hasAction ? '5' : '6'"
            :md="hasAction ? '5' : '6'"
            sm="12"
            xs="12"
          >
            <v-menu
              :ref="startDateID"
              v-model="form.startDate.isOpen"
              :close-on-content-click="false"
              :return-value.sync="form.startDate.value"
              :disabled="disabled"
              transition="scale-transition"
              offset-y
              min-width="290px"
            >
              <template v-slot:activator="{ on, attrs }">
                <div
                  v-bind="attrs"
                  v-on="on"
                >
                  <v-text-field
                    v-model="getStartDateFormatted"
                    :rules="form.startDate.rules"
                    :reactive="true"
                    :label="$i18n.t('globals.start_date')"
                    prepend-icon="mdi-calendar"
                    readonly
                  />
                </div>
              </template>

              <v-date-picker
                v-model="form.startDate.value"
                :max="getMaxDate"
                no-title
                scrollable
                :locale="$i18n.locale"
                @change="hasAction ? null : emitChanges()"
                @input="$refs[startDateID].save(form.startDate.value)"
              />
            </v-menu>
          </v-col>

          <v-col
            cols="12"
            :xl="hasAction ? '5' : '6'"
            :lg="hasAction ? '5' : '6'"
            :md="hasAction ? '5' : '6'"
            sm="12"
            xs="12"
          >
            <v-menu
              :ref="endDateID"
              v-model="form.endDate.isOpen"
              :close-on-content-click="false"
              :return-value.sync="form.endDate.value"
              transition="scale-transition"
              :disabled="disabled"
              offset-y
              min-width="290px"
            >
              <template v-slot:activator="{ on, attrs }">
                <div
                  v-bind="attrs"
                  v-on="on"
                >
                  <v-text-field
                    v-model="getEndDateFormatted"
                    :rules="form.endDate.rules"
                    :label="$i18n.t('globals.end_date')"
                    prepend-icon="mdi-calendar"
                    readonly
                  />
                </div>
              </template>

              <v-date-picker
                v-model="form.endDate.value"
                :min="getMinDate"
                no-title
                scrollable
                :locale="$i18n.locale"
                @change="hasAction ? null : emitChanges()"
                @input="$refs[endDateID].save(form.endDate.value)"
              />
            </v-menu>
          </v-col>

          <v-col
            v-if="hasAction"
            cols="12"
            xl="1"
            lg="1"
            md="1"
            sm="12"
            xs="12"
            align="center"
            justify="center"
          >
            <v-btn
              icon
              :disabled="disabled"
              @click="emitChanges()"
            >
              <v-icon>mdi-magnify</v-icon>
            </v-btn>
          </v-col>
        </v-row>
      </v-container>
    </v-form>
  </v-container>
</template>

<script src="./script.js"></script>
