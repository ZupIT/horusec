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
    class="company gradient-container"
    @click="!isLoading ? reset() : null"
  >
    <v-card
      elevation="10"
      :loading="isLoading"
      :disabled="isLoading"
    >
      <v-toolbar
        color="light-dark"
        dark
        :class="{'header-opened': isSearch }"
      >
        <v-toolbar-title>{{ $i18n.t('company.title') }}</v-toolbar-title>

        <v-spacer />

        <v-btn
          icon
          @click.stop="isSearch = !isSearch"
        >
          <v-icon>mdi-magnify</v-icon>
        </v-btn>

        <v-dialog
          v-model="form.isOpen"
          width="500"
          :disabled="isLoading"
          persistent
        >
          <template v-slot:activator="{ on, attrs }">
            <v-btn
              icon
              v-bind="attrs"
              v-on="on"
              @click.stop="openModalToCreate()"
            >
              <v-icon>mdi-plus-circle</v-icon>
            </v-btn>
          </template>

          <v-card
            :loading="isLoading"
            :disabled="isLoading"
          >
            <v-card-title
              v-if="form.type === 'edit'"
              class="white--text grey darken-4"
              primary-title
            >
              {{ $i18n.t('company.title_edit_company') }}
            </v-card-title>

            <v-card-title
              v-if="form.type === 'create'"
              class="white--text grey darken-4"
              primary-title
            >
              {{ $i18n.t('company.title_add_company') }}
            </v-card-title>

            <v-card-title
              v-if="form.type === 'delete'"
              class="white--text grey darken-4"
              primary-title
            >
              {{ $i18n.t('company.title_delete_company') }}
            </v-card-title>

            <v-container v-if="form.type === 'delete'">
              <span v-html="$i18n.t('company.modal_delete_description', {companyName: form.companyName.value})" />
            </v-container>

            <v-form
              v-if="form.type !== 'delete'"
              ref="form"
              v-model="form.valid"
              @submit.prevent
            >
              <v-container>
                <v-row>
                  <v-col cols="12">
                    <v-text-field
                      v-model="form.companyName.value"
                      :rules="form.companyName.rules"
                      :label="$i18n.t('company.form.company_name_field')"
                      required
                      light
                      @keypress.enter="form.valid ? form.type === 'edit' ? editCompany() : createCompany() : null"
                    />
                  </v-col>
                </v-row>
              </v-container>
            </v-form>

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
                @click="createCompany()"
              >
                {{ $i18n.t('globals.form.btn_save') }}
              </v-btn>

              <v-btn
                v-if="form.type === 'edit'"
                color="gray success"
                large
                :disabled="!form.valid"
                @click="editCompany()"
              >
                {{ $i18n.t('globals.form.btn_save') }}
              </v-btn>

              <v-btn
                v-if="form.type === 'delete'"
                color="gray error"
                large
                @click="deleteCompany()"
              >
                {{ $i18n.t('globals.form.btn_delete') }}
              </v-btn>
            </v-card-actions>
          </v-card>
        </v-dialog>
      </v-toolbar>

      <v-container
        class="search-container"
        :class="{'opened': isSearch}"
        @click.stop
      >
        <v-row>
          <v-col cols="12">
            <v-text-field
              v-model="search"
              :label="$i18n.t('company.search_field')"
            />
          </v-col>
        </v-row>
      </v-container>

      <v-list>
        <v-list-item
          v-for="company in searchedCompany"
          :key="company.title"
          @dblclick="selectCompay(company)"
          @click="selectCompay(company)"
        >
          <v-list-item-content>
            <v-list-item-title>
              {{ company.name }}
            </v-list-item-title>
          </v-list-item-content>

          <v-list-item-action
            @dblclick.stop
            @click.stop
          >
            <v-menu
              bottom
              offset-y
            >
              <template v-slot:activator="{ on, attrs }">
                <v-btn
                  icon
                  v-bind="attrs"
                  v-on="on"
                >
                  <v-icon>mdi-dots-vertical</v-icon>
                </v-btn>
              </template>
              <v-list>
                <v-list-item
                  v-for="(action, i) in [ $i18n.t('company.actions.select'), $i18n.t('company.actions.edit'), $i18n.t('company.actions.delete') ]"
                  :key="i"
                  @click="callActionInCompany(action, company)"
                >
                  <v-list-item-title>{{ action }}</v-list-item-title>
                </v-list-item>
              </v-list>
            </v-menu>
          </v-list-item-action>
        </v-list-item>

        <v-list-item v-if="searchedCompany.length === 0">
          <v-list-item-content>
            <v-list-item-subtitle v-text="$i18n.t('globals.toast.not_found')" />
          </v-list-item-content>
        </v-list-item>
      </v-list>

      <v-divider />

      <v-row align="center">
        <v-col
          class="text-center"
          cols="12"
        >
          <v-btn
            color="gray dark-4"
            icon
            @click="logout()"
          >
            <v-icon>mdi-power-standby</v-icon>
          </v-btn>
        </v-col>
      </v-row>
    </v-card>

    <Footer />
  </section>
</template>

<style lang="scss">
  @import './style.scss';
</style>

<script src="./script.js" />
