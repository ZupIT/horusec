/**
 * Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import axios, { AxiosInstance, AxiosResponse, AxiosRequestConfig } from 'axios';
import accountService from 'services/account';
import { getAccessToken } from 'helpers/localStorage/tokens';

const instance: AxiosInstance = axios.create({
  timeout: 5000,
  headers: {
    'Content-Type': 'application/json',
  },
});

instance.interceptors.request.use(async (config: AxiosRequestConfig) => {
  const accessToken = getAccessToken();

  if (accessToken) {
    config.headers.common['Authorization'] = `Bearer ${accessToken}`;
  }

  return config;
});

instance.interceptors.response.use(async (response: AxiosResponse) => {
  await accountService.callRenewToken();

  return response;
});

export default instance;
