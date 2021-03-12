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

import axios, { AxiosRequestConfig, AxiosInstance } from 'axios';
import { differenceInMinutes } from 'date-fns';
import accountService from 'services/account';
import {
  getExpiresTokenTime,
  getAccessToken,
  setTokens,
  clearTokens,
} from 'helpers/localStorage/tokens';
import { getCurrentConfig } from 'helpers/localStorage/horusecConfig';
import { authTypes } from 'helpers/enums/authTypes';
import { keycloakInstance } from './keycloak';
import { clearCurrentUser } from 'helpers/localStorage/currentUser';

const instance: AxiosInstance = axios.create({
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
});

instance.interceptors.request.use(async (config: AxiosRequestConfig) => {
  const expiresAt = getExpiresTokenTime();
  const expiresRemaining = differenceInMinutes(new Date(expiresAt), new Date());
  const isRenewTokenRoute = config.url.includes('renew-token');
  const MINUTES_RENEW = 5;

  if (
    expiresAt &&
    Math.abs(expiresRemaining) <= MINUTES_RENEW &&
    !isRenewTokenRoute
  ) {
    await accountService.callRenewToken();
  }

  const accessToken = getAccessToken();

  if (accessToken) {
    config.headers.common['X-Horusec-Authorization'] = `Bearer ${accessToken}`;
  }

  return config;
});

instance.interceptors.response.use(
  (response) => response,
  async (error) => {
    const status = error?.response ? error?.response?.status : null;
    const { authType } = getCurrentConfig();

    if (authType === authTypes.KEYCLOAK && status === 401) {
      try {
        await keycloakInstance.updateToken(0);

        if (!error.response.config._retry) {
          error.response.config._retry = true;

          const { token, refreshToken, idToken } = keycloakInstance;

          setTokens(token, refreshToken, null, idToken);

          error.response.config.headers['X-Horusec-Authorization'] = token;

          return axios(error.response.config);
        }

        return Promise.reject(error);
      } catch {
        clearCurrentUser();
        clearTokens();
        window.location.replace('/auth');
      }
    }

    return Promise.reject(error);
  }
);

export default instance;
