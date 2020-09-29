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
  <div class="internal">
    <router-view v-if="$route.name === 'company'" />

    <div
      v-if="$route.name !== 'company'"
      style="height: 100%;"
    >
      <v-navigation-drawer
        v-model="navigationDrawerIsOpen"
        style="height: 100vh;"
        fixed
        temporary
      >
        <div class="header-horusec">
          <HorusecLogo />
        </div>

        <div class="company-selected">
          <v-icon>mdi-domain</v-icon>

          <strong>
            {{ getterSelectedCompany.name }}
          </strong>
        </div>

        <v-divider />

        <v-card
          elevation="0"
          :disabled="isLogout"
          :loading="isLogout"
        >
          <v-list
            dense
            nav
          >
            <v-list-item
              v-for="item in navigationDrawerItems"
              :key="item.title"
              link
              @click="factoryMenu(item.type)"
            >
              <v-list-item-icon>
                <v-icon>{{ item.icon }}</v-icon>
              </v-list-item-icon>

              <v-list-item-content>
                <v-list-item-title>
                  {{ $i18n.t(item.title) }}
                </v-list-item-title>
              </v-list-item-content>
            </v-list-item>
          </v-list>
        </v-card>

        <template v-slot:append>
          <Footer />

          <v-row align="center">
            <v-col
              class="text-center"
              cols="12"
            >
              <v-btn
                color="gray dark-4"
                icon
                :disabled="isLogout"
                @click="logout()"
              >
                <v-icon>mdi-power-standby</v-icon>
              </v-btn>
            </v-col>
          </v-row>
        </template>
      </v-navigation-drawer>

      <div class="internal-wrapper">
        <v-toolbar color="blue darken-4 primary">
          <v-app-bar-nav-icon
            color="white"
            @click.stop="navigationDrawerIsOpen = !navigationDrawerIsOpen"
          />

          <v-toolbar-title>
            <span class="white--text">{{ $i18n.t(getTitleByRoute) }}</span>
          </v-toolbar-title>

          <v-spacer />

          <v-tooltip bottom>
            <template v-slot:activator="{ on, attrs }">
              <v-icon
                color="white"
                v-bind="attrs"
                v-on="on"
              >
                mdi-help-circle
              </v-icon>
            </template>

            <span>{{ $i18n.t(getDescriptionByRoute) }}</span>
          </v-tooltip>
        </v-toolbar>

        <router-view
          v-if="!isLogout"
          class="internal-routes"
        />
      </div>
    </div>
  </div>
</template>

<style lang="scss">
  @import './style.scss';
</style>

<script src="./script.js" />
