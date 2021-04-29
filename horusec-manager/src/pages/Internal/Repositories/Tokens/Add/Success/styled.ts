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

interface TokenWrapperProps {
  isCopy: boolean;
}

const Background = styled.div`
  width: 100vw;
  height: 100vh;
  position: fixed;
  background-color: ${({ theme }) => theme.colors.dialog.backgroundScreen};
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 3;
  top: 0;
  left: 0;
`;

const Wrapper = styled.div`
  background-color: ${({ theme }) => theme.colors.dialog.background};
  width: 520px;
  padding: 30px 40px;
  border-radius: 4px;
  display: flex;
  align-items: center;
  flex-direction: column;
`;

const Head = styled.div`
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 40px;
`;

const Title = styled.h2`
  color: ${({ theme }) => theme.colors.text.primary};
  font-size: ${({ theme }) => theme.metrics.fontSize.large};
  font-weight: normal;
  margin-left: 25px;
`;

const TokenWrapper = styled.div<TokenWrapperProps>`
  background-color: ${({ theme }) => theme.colors.background.highlight};
  display: flex;
  align-items: center;
  justify-content: space-evenly;
  border-radius: 4px;
  width: 100%;
  padding: 10px;
  ${({ isCopy }) =>
    isCopy &&
    css`
      background-color: ${({ theme }) => theme.colors.success};
    `};

  :hover {
    cursor: pointer;

    .copy {
      transform: scale(1.3);
    }
  }
`;

const Token = styled.h3`
  color: ${({ theme }) => theme.colors.text.primary};
  font-size: ${({ theme }) => theme.metrics.fontSize.xlarge};
  font-weight: bold;
  margin-right: 5px;
`;

const Info = styled.span`
  padding: 20px;
  margin: 20px 0;
  display: block;
  color: ${({ theme }) => theme.colors.text.primary};
  font-size: ${({ theme }) => theme.metrics.fontSize.medium};
`;

export default {
  Background,
  Wrapper,
  Head,
  Title,
  TokenWrapper,
  Token,
  Info,
};
