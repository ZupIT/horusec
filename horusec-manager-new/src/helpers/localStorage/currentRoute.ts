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
import { InternalRoute } from 'helpers/interfaces/InternalRoute';

const getCurrentRoute = (): InternalRoute | null => {
  const localData: InternalRoute = JSON.parse(
    window.localStorage.getItem(localStorageKeys.ROUTE)
  );

  return localData;
};

const setCurrenRoute = (value: InternalRoute) => {
  const route = JSON.stringify(value);
  window.localStorage.setItem(localStorageKeys.ROUTE, route);
};

const clearCurrentRoute = () => {
  window.localStorage.removeItem(localStorageKeys.ROUTE);
};

export { getCurrentRoute, setCurrenRoute, clearCurrentRoute };
