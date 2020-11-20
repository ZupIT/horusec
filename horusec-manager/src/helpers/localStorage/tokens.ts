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
import moment from 'moment';
import { getCurrentConfig } from './horusecConfig';
import { authTypes } from 'helpers/enums/authTypes';
import accountService from 'services/account';
import { setCurrentUser } from './currentUser';
import { isAuthenticatedInMicrofrontend } from 'helpers/localStorage/microfrontend';
import {
  setLocalStorage,
  getLocalStorage,
  removeLocalStorage,
} from 'helpers/localStorage/base';

const getAccessToken = (): string => {
  return getLocalStorage(localStorageKeys.ACCESS_TOKEN);
};

const getRefreshToken = (): string => {
  return getLocalStorage(localStorageKeys.REFRESH_TOKEN);
};

const getExpiresTokenTime = (): string => {
  return getLocalStorage(localStorageKeys.TOKEN_EXPIRES);
};

const setTokens = (
  accessToken: string,
  refreshToken: string,
  expiresAt?: string
) => {
  if (accessToken) setLocalStorage(localStorageKeys.ACCESS_TOKEN, accessToken);

  if (refreshToken)
    setLocalStorage(localStorageKeys.REFRESH_TOKEN, refreshToken);

  if (expiresAt) setLocalStorage(localStorageKeys.TOKEN_EXPIRES, expiresAt);
};

const handleSetKeyclockData = async (
  accessToken: string,
  refreshToken: string
) => {
  const currentAccessToken = getAccessToken();

  if (accessToken && accessToken !== currentAccessToken) {
    accountService.createAccountFromKeycloak(accessToken).then((result) => {
      const userData = result?.data?.content;
      setCurrentUser(userData);

      if (window.location.pathname === '/auth') {
        window.location.replace('/home');
      }
    });
  }

  setTokens(accessToken, refreshToken);
};

const clearTokens = () => {
  removeLocalStorage(localStorageKeys.ACCESS_TOKEN);
  removeLocalStorage(localStorageKeys.REFRESH_TOKEN);
  removeLocalStorage(localStorageKeys.TOKEN_EXPIRES);
};

const isLogged = (): boolean => {
  const { authType } = getCurrentConfig();
  const accessToken = getAccessToken();

  if (
    (authType === authTypes.KEYCLOAK && accessToken) ||
    isAuthenticatedInMicrofrontend()
  ) {
    return true;
  }

  if (authType === authTypes.HORUSEC || authType === authTypes.LDAP) {
    const expiresAt = getLocalStorage(localStorageKeys.TOKEN_EXPIRES);

    if (!accessToken || !expiresAt) return false;

    const now = moment();
    const expiresTime = moment(expiresAt);

    return expiresTime.isSameOrAfter(now);
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
