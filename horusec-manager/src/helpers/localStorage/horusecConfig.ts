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
import { HorusecConfig } from 'helpers/interfaces/HorusecConfig';

const initialValues: HorusecConfig = {
  authType: 'horusec',
  applicationAdminEnable: false,
  disabledBroker: true,
};

const getCurrentConfig = (): HorusecConfig => {
  try {
    const config = window.localStorage.getItem(localStorageKeys.CONFIG);
    return config ? JSON.parse(config) : initialValues;
  } catch (e) {
    return initialValues;
  }
};

const setCurrenConfig = (value: HorusecConfig) => {
  window.localStorage.setItem(localStorageKeys.CONFIG, JSON.stringify(value));
};

const clearCurrentConfig = () => {
  window.localStorage.removeItem(localStorageKeys.CONFIG);
};

export { getCurrentConfig, setCurrenConfig, clearCurrentConfig };
