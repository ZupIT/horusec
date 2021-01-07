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

import accountService from 'services/account';
import { setTokens } from 'helpers/localStorage/tokens';
import { setCurrentUser } from 'helpers/localStorage/currentUser';
import { LoginParams } from 'helpers/interfaces/LoginParams';

const login = (params: LoginParams) => {
  return new Promise((resolve, reject) => {
    accountService
      .login(params)
      .then((result) => {
        const userData = result?.data?.content;
        const { accessToken, refreshToken, expiresAt } = userData;

        setCurrentUser(userData);
        setTokens(accessToken, refreshToken, expiresAt);
        resolve(result);
      })
      .catch((err) => reject(err));
  });
};

const logout = () => accountService.logout();

export default {
  login,
  logout,
};
