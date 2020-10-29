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
import { User } from 'helpers/interfaces/User';
import { getCurrentConfig } from './horusecConfig';

const getCurrentUser = (): User | null => {
  const localData: User = JSON.parse(
    window.localStorage.getItem(localStorageKeys.USER)
  );

  return localData;
};

const setCurrentUser = (value: User) => {
  const { username, email, isApplicationAdmin } = value;

  const user = JSON.stringify({ username, email, isApplicationAdmin });
  window.localStorage.setItem(localStorageKeys.USER, user);
};

const clearCurrentUser = () => {
  window.localStorage.removeItem(localStorageKeys.USER);
};

const isApplicationAdmin = () => {
  const { applicationAdminEnable } = getCurrentConfig();
  const { isApplicationAdmin } = getCurrentUser();

  return !applicationAdminEnable ? false : isApplicationAdmin;
};

export { getCurrentUser, setCurrentUser, clearCurrentUser, isApplicationAdmin };
