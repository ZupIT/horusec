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
      <v-card-title class="d-flex justify-center full-width">
        <v-dialog
          v-model="form.isOpen"
          width="500"
          :disabled="isLoading"
        >
          <template v-slot:activator="{ on, attrs }">
            <v-btn
              class="btn-action-item"
              color="blue darken-2"
              medium
              v-bind="attrs"
              v-on="on"
              @click="setCreateItem()"
            >
              <span class="white--text">{{ $i18n.t('repository.tokens.btn_create') }}</span>

              <v-icon
                color="white"
                style="margin-left: 10px;"
              >
                mdi-plus-circle
              </v-icon>
            </v-btn>
          </template>

          <v-card
            :disabled="isLoading"
            :loading="isLoading"
          >
            <v-card-title
              v-if="form.type === 'create'"
              class="white--text grey darken-4"
            >
              {{ $i18n.t('repository.tokens.title_modal_create') }}
            </v-card-title>

            <v-card-title
              v-if="form.type === 'delete'"
              class="white--text grey darken-4"
            >
              {{ $i18n.t('repository.tokens.title_modal_delete') }}
            </v-card-title>

            <v-container v-if="form.type === 'delete'">
              <span v-html="$i18n.t('repository.tokens.content_modal_delete_token', {description: form.description.value})" />
            </v-container>

            <v-container v-if="form.type === 'create'">
              <v-form
                ref="form"
                v-model="form.valid"
                @submit.prevent
              >
                <v-container>
                  <v-row>
                    <v-col cols="12">
                      <v-text-field
                        v-model="form.description.value"
                        :rules="form.description.rules"
                        :label="$i18n.t('repository.tokens.form.description_field')"
                        required
                        light
                        @keypress.enter="form.valid ? createToken() : null"
                      />
                    </v-col>
                  </v-row>
                </v-container>
              </v-form>
            </v-container>

            <v-container v-if="form.type === 'create_success'">
              <v-alert
                icon="mdi-shield-lock-outline"
                prominent
                text
                type="info"
              >
                <h3 class="headline">
                  {{ $i18n.t('repository.tokens.form.created_success_title') }}
                </h3>

                <v-divider
                  class="my-4 info"
                  style="opacity: 0.22;"
                />

                <v-row class="d-flex justify-center full-width">
                  <v-col
                    cols="12"
                    class="d-flex justify-center full-width"
                  >
                    <h1>{{ form.token.value }}</h1>
                  </v-col>
                </v-row>

                <v-row
                  align="center"
                  no-gutters
                >
                  <v-col cols="12">
                    <span v-html="$i18n.t('repository.tokens.form.created_success_description')" />
                  </v-col>
                </v-row>
              </v-alert>
            </v-container>

            <v-divider />

            <v-card-actions
              :class="form.type === 'create_success' ? 'd-flex justify-center full-width' : ''"
            >
              <v-btn
                v-if="form.type !== 'create_success'"
                color="gray"
                large
                @click.stop="reset()"
              >
                {{ $i18n.t('globals.form.btn_cancel') }}
              </v-btn>

              <v-btn
                v-if="form.type === 'create_success'"
                color="gray"
                large
                @click.stop="reset(); getAllTokens()"
              >
                {{ $i18n.t('globals.close') }}
              </v-btn>

              <v-spacer v-if="form.type !== 'create_success'" />

              <v-btn
                v-if="form.type === 'create'"
                color="gray success"
                large
                :disabled="!form.valid"
                @click="createToken()"
              >
                {{ $i18n.t('globals.form.btn_save') }}
              </v-btn>

              <v-btn
                v-if="form.type === 'delete'"
                color="gray error"
                large
                @click="deleteToken()"
              >
                {{ $i18n.t('globals.form.btn_delete') }}
              </v-btn>
            </v-card-actions>
          </v-card>
        </v-dialog>
      </v-card-title>

      <v-data-table
        :headers="tableHeaders"
        :items="table.content"
        :loading="isLoading"
        loading-text=""
        class="elevation-1"
        height="288"
      >
        <template v-slot:no-data>
          {{ $i18n.t('globals.not_found') }}
        </template>

        <template v-slot:item.actions="{ item }">
          <v-btn
            class="btn-action-item"
            icon
            medium
            @click="setDeleteItem(item)"
          >
            <v-icon
              color="red darken-4"
            >
              mdi-delete
            </v-icon>
          </v-btn>
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
