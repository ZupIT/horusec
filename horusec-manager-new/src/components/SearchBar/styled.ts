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

const Wrapper = styled.section`
  width: 100%;
  padding: 18px;
  background-color: ${({ theme }) => theme.colors.background.highlight};
  border-radius: 4px;
  display: flex;
  align-items: center;
  margin-right: 20px;
`;

const Input = styled.input`
  width: 100%;
  margin: 0px 10px;
  background: none;
  border: none;
  outline: none;
  color: ${({ theme }) => theme.colors.input.text};
  font-size: ${({ theme }) => theme.metrics.fontSize.small};

  ::placeholder {
    color: ${({ theme }) => theme.colors.input.text};
    font-size: ${({ theme }) => theme.metrics.fontSize.small};
  }

  :-ms-input-placeholder {
    color: ${({ theme }) => theme.colors.input.text};
    font-size: ${({ theme }) => theme.metrics.fontSize.small};
  }

  ::-ms-input-placeholder {
    color: ${({ theme }) => theme.colors.input.text};
    font-size: ${({ theme }) => theme.metrics.fontSize.small};
  }
`;

export default {
  Wrapper,
  Input,
};
