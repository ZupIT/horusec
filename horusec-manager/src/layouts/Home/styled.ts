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

import styled, { css } from 'styled-components';
import { isMicrofrontend } from 'helpers/localStorage/microfrontend';

const Wrapper = styled.div`
  display: flex;

  ${isMicrofrontend()
    ? css`
        height: calc(96.3vh - 50px);
      `
    : css`
        height: 96.3vh;
      `}
`;

export default { Wrapper };
