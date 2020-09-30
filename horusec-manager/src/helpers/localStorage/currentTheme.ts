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

import * as THEME from 'config/themes';
import get from 'lodash/get';
import { localStorageKeys } from 'helpers/enums/localStorageKeys';

const getCurrentTheme = () => {
  const currentTheme =
    window.localStorage.getItem(localStorageKeys.THEME) || 'dark';
  return get(THEME, currentTheme, THEME.dark);
};

const setCurrentTheme = (value: 'dark' | 'light') => {
  window.localStorage.setItem(localStorageKeys.USER, value);
};

export { getCurrentTheme, setCurrentTheme };
