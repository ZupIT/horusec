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

const isMicrofrontend = (): boolean => {
  return window.localStorage.getItem(localStorageKeys.MICROFRONTEND) === 'true';
};

const isAuthenticatedInMicrofrontend = (): boolean => {
  return window.localStorage.getItem(localStorageKeys.AUTHENTICATED) === 'true';
};

const setIsMicrofrontend = (value: boolean) => {
  window.localStorage.setItem(
    localStorageKeys.MICROFRONTEND,
    JSON.stringify(value)
  );
};

export { isMicrofrontend, isAuthenticatedInMicrofrontend, setIsMicrofrontend };
