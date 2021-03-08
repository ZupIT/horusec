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

import { localStorageKeys } from 'helpers/enums/localStorageKeys';
import { isPast } from 'date-fns';
import { getCurrentConfig } from './horusecConfig';
import { authTypes } from 'helpers/enums/authTypes';

const getAccessToken = (): string => {
  return window.localStorage.getItem(localStorageKeys.ACCESS_TOKEN);
};

const getRefreshToken = (): string => {
  return window.localStorage.getItem(localStorageKeys.REFRESH_TOKEN);
};

const getExpiresTokenTime = (): string => {
  return window.localStorage.getItem(localStorageKeys.TOKEN_EXPIRES);
};

const setTokens = (
  accessToken: string,
  refreshToken: string,
  expiresAt?: string,
  idToken?: string
) => {
  if (accessToken)
    window.localStorage.setItem(localStorageKeys.ACCESS_TOKEN, accessToken);

  if (refreshToken)
    window.localStorage.setItem(localStorageKeys.REFRESH_TOKEN, refreshToken);

  if (expiresAt)
    window.localStorage.setItem(localStorageKeys.TOKEN_EXPIRES, expiresAt);

  if (idToken) window.localStorage.setItem(localStorageKeys.ID_TOKEN, idToken);
};

const clearTokens = () => {
  window.localStorage.removeItem(localStorageKeys.ACCESS_TOKEN);
  window.localStorage.removeItem(localStorageKeys.REFRESH_TOKEN);
  window.localStorage.removeItem(localStorageKeys.TOKEN_EXPIRES);
  window.localStorage.removeItem(localStorageKeys.ID_TOKEN);
};

const handleSetKeyclockData = async (
  accessToken: string,
  refreshToken: string,
  idToken: string
) => {
  setTokens(accessToken, refreshToken, null, idToken);
};

const isLogged = (): boolean => {
  const { authType } = getCurrentConfig();
  const accessToken = getAccessToken();

  if (authType === authTypes.KEYCLOAK) {
    return true;
  }

  if (authType === authTypes.HORUSEC || authType === authTypes.LDAP) {
    const expiresAt = window.localStorage.getItem(
      localStorageKeys.TOKEN_EXPIRES
    );

    if (!accessToken || !expiresAt) return false;

    return !isPast(new Date(expiresAt));
  }

  return false;
};

export {
  getAccessToken,
  getRefreshToken,
  clearTokens,
  setTokens,
  isLogged,
  getExpiresTokenTime,
  handleSetKeyclockData,
};
