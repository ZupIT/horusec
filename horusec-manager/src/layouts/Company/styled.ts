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

interface SettingsProps {
  isVisible: boolean;
}

interface ItemProps {
  selected: boolean;
}

const Wrapper = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  padding-bottom: 50px;

  ${isMicrofrontend()
    ? css`
        height: calc(100vh - 50px);
      `
    : css`
        height: 100vh;
      `}
`;

const Container = styled.div`
  display: flex;
  align-items: center;
  justify-content: center;
  flex: 1;
  width: 100%;
`;

const Content = styled.div`
  padding: 40px;
  background-color: ${({ theme }) => theme.colors.background.overlap};
  border-radius: 4px;
  width: 90%;
  max-width: 700px;
`;

const Footer = styled.footer`
  position: relative;
  display: flex;
  flex-direction: row-reverse;
  align-items: center;
  justify-content: center;
  width: 100%;

  @media (max-width: 768px) {
    flex-direction: column-reverse;
  }
`;

const LanguageWrapper = styled.div`
  position: absolute;
  left: 10%;
  margin-bottom: 40px;

  @media (max-width: 768px) {
    position: relative;
    left: 0;
  }
`;

export default {
  Wrapper,
  Content,
  Footer,
  LanguageWrapper,
  Container,
};
