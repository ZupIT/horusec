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

import dark from './dark';

export default {
  ...dark,
  colors: {
    ...dark.colors,

    button: {
      primary: '#5C6BC0',
      secundary: '#5C6BC0',
      text: '#F2F2F9',
      border: '#F2F2F7',
      disabled: '#2C2C2E',
      disableInDark: '#636366',
    },
  },
};
