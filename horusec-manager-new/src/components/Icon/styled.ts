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
import { Props } from '.';

type WrapperProps = Pick<Props, 'size' | 'onClick'>;

const Icon = styled.i<WrapperProps>`
  display: inline-flex;
  color: ${({ theme }) => theme.colors.icon.primary};

  ${({ size }) =>
    size &&
    css`
      width: ${size};
      height: ${size};
    `};

  ${({ onClick }) =>
    onClick &&
    css`
      background: none;
      border: none;
      cursor: pointer;
      transition: 0.2s;
      padding: 0;

      :hover {
        transform: scale(1.1);
      }
    `};

  > div > div {
    display: flex;
  }

  svg {
    ${({ size }) =>
      size &&
      css`
        width: ${size};
        height: ${size};
      `};
  }
`;

export default {
  Icon,
};
