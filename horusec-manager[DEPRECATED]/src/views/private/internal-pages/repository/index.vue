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
  <section class="repository">
    <v-card>
      <v-card-title>
        <v-text-field
          v-model="search"
          :label="$i18n.t('repository.table.search_name')"
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
                <span class="white--text">{{ $i18n.t('repository.table.btn_create') }}</span>

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
            :disabled="item.role !== 'member'"
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
                  :disabled="item.role === 'member'"
                  style="margin-right: 15px;"
                  :title="$i18n.t('repository.table.btn_lock_title')"
                  @click="setEditTokens(item)"
                >
                  <v-icon
                    color="grey darken-4"
                  >
                    mdi-lock-open
                  </v-icon>
                </v-btn>

                <v-btn
                  class="btn-action-item"
                  icon
                  medium
                  :disabled="item.role === 'member'"
                  style="margin-right: 15px;"
                  :title="$i18n.t('repository.table.btn_account_title')"
                  @click="setEditUsers(item)"
                >
                  <v-icon
                    color="grey darken-4"
                  >
                    mdi-account-group
                  </v-icon>
                </v-btn>

                <v-btn
                  class="btn-action-item"
                  icon
                  medium
                  :disabled="item.role === 'member'"
                  style="margin-right: 15px;"
                  :title="$i18n.t('repository.table.btn_edit_title')"
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
                  :disabled="item.role === 'member'"
                  :title="$i18n.t('repository.table.btn_remove_title')"
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

            <span>{{ $i18n.t('globals.tooltip.user_without_permission') }}</span>
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
          {{ $i18n.t('repository.title_edit_repository') }}
        </v-card-title>

        <v-card-title
          v-if="form.type === 'create'"
          class="white--text grey darken-4"
          primary-title
        >
          {{ $i18n.t('repository.title_add_repository') }}
        </v-card-title>

        <v-card-title
          v-if="form.type === 'delete'"
          class="white--text grey darken-4"
          primary-title
        >
          {{ $i18n.t('repository.title_delete_repository') }}
        </v-card-title>

        <v-container v-if="form.type === 'delete'">
          <span v-html="$i18n.t('repository.modal_delete_repository', {username: form.name.value})" />
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
                    v-model="form.name.value"
                    :rules="form.name.rules"
                    :label="$i18n.t('repository.form.name_field')"
                    required
                    light
                    @keypress.enter="form.valid ? form.type === 'edit' ? editRepository() : createRepository() : null"
                  />
                </v-col>
              </v-row>

              <v-row>
                <v-col cols="12">
                  <v-text-field
                    v-model="form.description.value"
                    :rules="form.description.rules"
                    :label="$i18n.t('repository.form.description_field')"
                    required
                    light
                    @keypress.enter="form.valid ? form.type === 'edit' ? editRepository() : createRepository() : null"
                  />
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
            @click="createRepository()"
          >
            {{ $i18n.t('globals.form.btn_save') }}
          </v-btn>

          <v-btn
            v-if="form.type === 'edit'"
            color="gray success"
            large
            :disabled="!form.valid"
            @click="editRepository()"
          >
            {{ $i18n.t('globals.form.btn_save') }}
          </v-btn>

          <v-btn
            v-if="form.type === 'delete'"
            color="gray error"
            large
            @click="deleteRepository()"
          >
            {{ $i18n.t('globals.form.btn_delete') }}
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <v-dialog
      v-if="repositorySelected.type === 'users'"
      v-model="repositorySelected.isOpen"
      width="675"
      :disabled="isLoading"
      persistent
    >
      <UsersRepository
        :repository-id="repositorySelected.value.repositoryID"
        @onClose="reset()"
      />
    </v-dialog>

    <v-dialog
      v-if="repositorySelected.type === 'tokens'"
      v-model="repositorySelected.isOpen"
      width="675"
      :disabled="isLoading"
      persistent
    >
      <TokensRepository
        :repository-id="repositorySelected.value.repositoryID"
        @onClose="reset()"
      />
    </v-dialog>
  </section>
</template>

<script src="./script.js" />
