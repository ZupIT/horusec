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
    elevation="10"
    :loading="isLoading"
    :disabled="isLoading"
  >
    <v-form
      v-model="form.valid"
      @submit.prevent
    >
      <HorusecLogo />

      <v-container>
        <v-row>
          <v-col cols="12">
            <v-text-field
              v-model="form.code.value"
              :rules="form.code.rules"
              :label="$i18n.t('recovery_password.form.code_field')"
              required
              light
              @keypress.enter="form.valid ? submit() : null"
            />
          </v-col>
        </v-row>
      </v-container>

      <v-btn
        color="primary"
        large
        :disabled="!form.valid"
        @click="submit()"
      >
        {{ $i18n.t('recovery_password.form.btn_check_code') }}
      </v-btn>

      <v-btn
        color="primary lighten"
        large
        @click="goToLogin()"
      >
        {{ $i18n.t('recovery_password.form.btn_login') }}
      </v-btn>
    </v-form>
  </v-card>
</template>

<script src="./script.js" />
