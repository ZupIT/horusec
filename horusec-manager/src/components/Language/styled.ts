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

import styled from 'styled-components';

const Wrapper = styled.div`
  width: 120px;
  height: 40px;
  border-radius: 4px;
  transition: all 0.3s;
`;

const CurrentLanguage = styled.span`
  margin-right: 10px;
  color: ${({ theme }) => theme.colors.text.primary};
  font-weight: bold;
`;

const Button = styled.button`
  background: linear-gradient(
    ${({ theme }) =>
      `90deg, ${theme.colors.button.primary} 0%, ${theme.colors.button.secundary} 100%`}
  );
  display: flex;
  justify-content: center;
  align-items: center;
  width: 100%;
  height: 100%;
  border: none;
  border-radius: 4px;
  color: ${({ theme }) => theme.colors.text.primary};
  font-size: ${({ theme }) => theme.metrics.fontSize.xsmall};
  cursor: pointer;

  :hover {
    opacity: 0.8;
  }
`;

const LanguagesList = styled.ul`
  background: linear-gradient(
    ${({ theme }) =>
      `90deg, ${theme.colors.button.primary} 0%, ${theme.colors.button.secundary} 100%`}
  );
  border-radius: 4px;
  list-style-type: none;
  outline: 1px white solid;
`;

const LanguageItem = styled.li`
  color: ${({ theme }) => theme.colors.text.primary};
  font-size: ${({ theme }) => theme.metrics.fontSize.xsmall};
  text-decoration: none;
  display: flex;
  align-items: center;
  justify-content: space-evenly;
  cursor: pointer;
  border-radius: 4px;
  transition: all 2s;
`;

export default {
  Wrapper,
  CurrentLanguage,
  Button,
  LanguagesList,
  LanguageItem,
};
