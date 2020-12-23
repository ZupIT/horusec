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

interface FlashWrapperProps {
  isVisible: boolean;
  type: 'success' | 'error' | 'warning';
}

const Wrapper = styled.div<FlashWrapperProps>`
  width: 100%;
  position: fixed;
  padding: 15px 0;
  bottom: -50px;
  transition: bottom 0.5s;
  z-index: 5;

  display: flex;
  align-items: center;
  justify-content: center;

  ${({ isVisible }) =>
    isVisible &&
    css`
      bottom: 0;
    `};

  ${({ type }) =>
    css`
      background-color: ${({ theme }) => theme.colors.flashMessage[type]};
    `};
`;

const Text = styled.span`
  display: block;
  text-align: center;
  color: ${({ theme }) => theme.colors.flashMessage.text};
  text-transform: uppercase;
  font-size: ${({ theme }) => theme.metrics.fontSize.medium};
  margin-left: 10px;
`;

export default { Wrapper, Text };
