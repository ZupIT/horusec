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

interface Props {
  isVisible: boolean;
}

const Container = styled.div<Props>`
  background-color: ${({ theme }) => theme.colors.background.primary};

  height: 100vh;
  width: 100%;

  position: fixed;
  z-index: 2;

  visibility: visible;
  opacity: 1;

  transition: all ease 1.5s;

  ${({ isVisible }) =>
    !isVisible &&
    css`
      opacity: 0;
      visibility: hidden;
    `};
`;

const Logo = styled.img<Props>`
  display: block;
  width: 266px;

  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);

  transition: top ease 1.5s;

  @media (max-width: 768px) {
    width: 220px;
  }

  ${({ isVisible }) =>
    !isVisible &&
    css`
      top: 25%;

      @media (max-width: 768px) {
        top: 20%;
      }
    `};
`;

export default {
  Container,
  Logo,
};
