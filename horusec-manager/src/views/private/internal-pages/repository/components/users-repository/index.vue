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
  <section class="users">
    <v-card>
      <v-card-title>
        <v-text-field
          v-model="search"
          :label="$i18n.t('user.table.search_email')"
          append-icon="mdi-magnify"
        />

        <v-spacer />

        <v-btn
          icon
          @click="isHelpPermission = !isHelpPermission"
        >
          <v-icon
            color="black"
          >
            mdi-help-circle
          </v-icon>
        </v-btn>
      </v-card-title>

      <v-row
        v-if="isHelpPermission"
        align="center"
      >
        <v-col cols="12">
          <v-container>
            <v-alert
              icon="mdi-lock-question"
              prominent
              text
              type="info"
            >
              <v-row
                align="center"
                no-gutters
              >
                <v-col cols="12">
                  <span v-html="$i18n.t('repository.users.form.help_permission_admin')" />

                  <hr style="margin: 10px 0;">

                  <span v-html="$i18n.t('repository.users.form.help_permission_member')" />
                </v-col>
              </v-row>
            </v-alert>
          </v-container>
        </v-col>
      </v-row>

      <v-data-table
        :headers="tableHeaders"
        :items="searchTableContent"
        :loading="isLoading"
        :disable-sort="isLoading"
        :disable-pagination="isLoading"
        :disable-filtering="isLoading"
        :show-select="true"
        :single-select="false"
        loading-text=""
        class="elevation-1"
        item-key="accountID"
        height="288"
      >
        <template v-slot:no-data>
          {{ $i18n.t('globals.not_found') }}
        </template>

        <template v-slot:header.data-table-select>
          {{ $i18n.t('globals.table.header_action') }}
        </template>

        <template v-slot:item.data-table-select="{ item }">
          <v-checkbox
            v-model="item.selected"
            :disabled="isLoading || (getterUserLogged.email === item.email)"
            @change="addOrRemoveUser(item)"
          />
        </template>

        <template v-slot:item.roleLabel="{ item }">
          <v-select
            v-model="item.role"
            :items="roles"
            item-text="name"
            item-value="value"
            style="max-width: 170px;"
            :disabled="isLoading || !item.selected || (getterUserLogged.email === item.email)"
            @change="updateUser($event, item)"
          />
        </template>
      </v-data-table>

      <v-card-actions class="d-flex justify-center full-width">
        <v-btn @click="$emit('onClose')">
          {{ $i18n.t('globals.close') }}
        </v-btn>
      </v-card-actions>
    </v-card>
  </section>
</template>

<script src="./script.js" />
