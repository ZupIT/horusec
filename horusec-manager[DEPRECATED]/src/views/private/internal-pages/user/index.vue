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

        <v-tooltip
          left
          :disabled="getterUserLogged.role !== 'member'"
        >
          <template v-slot:activator="{ on, attrs }">
            <div
              v-bind="attrs"
              v-on="on"
            >
              <v-btn
                class="btn-action-item"
                color="blue darken-2"
                medium
                :disabled="getterUserLogged.role === 'member'"
                @click="setCreateItem()"
              >
                <span class="white--text">{{ $i18n.t('user.table.btn_invate_user') }}</span>

                <v-icon
                  color="white"
                  style="margin-left: 10px;"
                >
                  mdi-plus-circle
                </v-icon>
              </v-btn>
            </div>
          </template>

          <span>{{ $i18n.t('globals.tooltip.user_without_permission') }}</span>
        </v-tooltip>
      </v-card-title>

      <v-data-table
        :headers="tableHeaders"
        :items="searchTableContent"
        :loading="isLoading"
        loading-text=""
        class="elevation-1"
      >
        <template v-slot:item.actions="{ item }">
          <v-tooltip
            left
            :disabled="!isToDisableAction(item.email)"
          >
            <template v-slot:activator="{ on, attrs }">
              <div
                v-bind="attrs"
                v-on="on"
              >
                <v-btn
                  class="btn-action-item"
                  icon
                  medium
                  style="margin-right: 15px;"
                  :disabled="isToDisableAction(item.email)"
                  @click="setEditItem(item)"
                >
                  <v-icon
                    color="grey darken-4"
                  >
                    mdi-pencil
                  </v-icon>
                </v-btn>

                <v-btn
                  class="btn-action-item"
                  icon
                  medium
                  :disabled="isToDisableAction(item.email)"
                  @click="setDeleteItem(item)"
                >
                  <v-icon
                    color="red darken-4"
                  >
                    mdi-delete
                  </v-icon>
                </v-btn>
              </div>
            </template>

            <span v-if="getterUserLogged.email === item.email">{{ $i18n.t('user.table.tooltip_disabled_action_yourself') }}</span>
            <span v-else-if="getterUserLogged.role === 'member'">{{ $i18n.t('globals.tooltip.user_without_permission') }}</span>
          </v-tooltip>
        </template>

        <template v-slot:no-data>
          {{ $i18n.t('globals.not_found') }}
        </template>
      </v-data-table>
    </v-card>

    <v-dialog
      v-model="form.isOpen"
      width="500"
      :disabled="isLoading"
      persistent
    >
      <v-card
        :loading="isLoading"
        :disabled="isLoading"
      >
        <v-card-title
          v-if="form.type === 'edit'"
          class="white--text grey darken-4"
          primary-title
        >
          {{ $i18n.t('user.title_edit_user') }}
        </v-card-title>

        <v-card-title
          v-if="form.type === 'create'"
          class="white--text grey darken-4"
          primary-title
        >
          {{ $i18n.t('user.title_add_user') }}
        </v-card-title>

        <v-card-title
          v-if="form.type === 'delete'"
          class="white--text grey darken-4"
          primary-title
        >
          {{ $i18n.t('user.title_delete_user') }}
        </v-card-title>

        <v-container v-if="form.type === 'delete'">
          <span v-html="$i18n.t('user.modal_delete_user', {username: form.userEmail.value})" />
        </v-container>

        <v-container v-if="form.type === 'edit' || form.type === 'create'">
          <v-form
            ref="form"
            v-model="form.valid"
            @submit.prevent
          >
            <v-container>
              <v-row>
                <v-col cols="12">
                  <v-text-field
                    v-model="form.userEmail.value"
                    :rules="form.userEmail.rules"
                    :label="$i18n.t('user.form.user_email_field')"
                    :disabled="form.type === 'edit'"
                    required
                    light
                    @keypress.enter="form.valid ? form.type === 'edit' ? editUser() : createUser() : null"
                  />
                </v-col>
              </v-row>

              <v-row justify="center">
                <v-col cols="10">
                  <v-select
                    v-model="form.userRole.value"
                    :items="roles"
                    :label="$i18n.t('user.form.user_role_field')"
                    :rules="form.userRole.rules"
                    item-text="name"
                    item-value="value"
                    dense
                    solo
                  />
                </v-col>

                <v-col cols="2">
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
                </v-col>
              </v-row>

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
                          <span v-html="$i18n.t('user.form.help_permission_admin')" />

                          <hr style="margin: 10px 0;">

                          <span v-html="$i18n.t('user.form.help_permission_member')" />
                        </v-col>
                      </v-row>
                    </v-alert>
                  </v-container>
                </v-col>
              </v-row>
            </v-container>
          </v-form>
        </v-container>

        <v-divider />

        <v-card-actions>
          <v-btn
            color="gray"
            large
            @click.stop="reset()"
          >
            {{ $i18n.t('globals.form.btn_cancel') }}
          </v-btn>

          <v-spacer />

          <v-btn
            v-if="form.type === 'create'"
            color="gray success"
            large
            :disabled="!form.valid"
            @click="createUser()"
          >
            {{ $i18n.t('globals.form.btn_save') }}
          </v-btn>

          <v-btn
            v-if="form.type === 'edit'"
            color="gray success"
            large
            :disabled="!form.valid"
            @click="editUser()"
          >
            {{ $i18n.t('globals.form.btn_save') }}
          </v-btn>

          <v-btn
            v-if="form.type === 'delete'"
            color="gray error"
            large
            @click="deleteUser()"
          >
            {{ $i18n.t('globals.form.btn_delete') }}
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </section>
</template>

<script src="./script.js" />
