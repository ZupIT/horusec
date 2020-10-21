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

import http from 'services/axios/default';
import axios from 'axios';
import { SERVICE_ACCOUNT } from './endpoints';
import {
  getCurrentUser,
  setCurrentUser,
  clearCurrentUser,
} from 'helpers/localStorage/currentUser';
import { AxiosResponse, AxiosError } from 'axios';
import { User } from 'helpers/interfaces/User';

const login = (email: string, password: string) => {
  return http.post(`${SERVICE_ACCOUNT}/api/account/login`, { email, password });
};

const logout = () => http.post(`${SERVICE_ACCOUNT}/api/account/logout`);

const createAccount = (username: string, password: string, email: string) => {
  return http.post(`${SERVICE_ACCOUNT}/api/account/create-account`, {
    username,
    email,
    password,
  });
};

const sendCode = (email: string) => {
  return http.post(`${SERVICE_ACCOUNT}/api/account/send-code`, { email });
};

const validateCode = (email: string, code: string) => {
  return http.post(`${SERVICE_ACCOUNT}/api/account/validate-code`, {
    email,
    code,
  });
};

const changePassword = (token: string, password: string) => {
  return http.post(`${SERVICE_ACCOUNT}/api/account/change-password`, password, {
    headers: {
      'Content-Type': 'text/plain',
      Authorization: `Bearer ${token}`,
    },
  });
};

const verifyUniqueUsernameEmail = (email: string, username: string) => {
  return http.post(`${SERVICE_ACCOUNT}/api/account/verify-already-used`, {
    email,
    username,
  });
};

const callRenewToken = async (): Promise<User | AxiosError> => {
  const { accessToken, refreshToken } = getCurrentUser();

  return new Promise((resolve, reject) => {
    axios
      .post(`${SERVICE_ACCOUNT}/api/account/renew-token`, refreshToken, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-type': 'text/plain',
        },
      })
      .then((result: AxiosResponse) => {
        const user = result.data?.content as User;

        if (user) {
          setCurrentUser(user);
        }

        resolve(user);
      })
      .catch((err: AxiosError) => {
        reject(err);
        clearCurrentUser();
        window.location.replace('/login');
      });
  });
};

const getAuthType = () => {
  return http.get('http://localhost:8006/api/auth/auth-types');
};

export default {
  login,
  logout,
  createAccount,
  sendCode,
  validateCode,
  changePassword,
  callRenewToken,
  verifyUniqueUsernameEmail,
  getAuthType,
};
