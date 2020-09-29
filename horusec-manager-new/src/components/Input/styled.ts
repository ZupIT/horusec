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
import { Icon } from 'components';

interface LabelProps {
  isFocused?: boolean;
}

interface InputProps {
  isInvalid?: boolean;
}

const Container = styled.div`
  display: block;
`;

const Input = styled.input<InputProps>`
  border: none;
  outline: none;
  background: transparent;
  border-bottom: 1px solid ${({ theme }) => theme.colors.input.border};
  color: ${({ theme }) => theme.colors.input.text};
  font-size: ${({ theme }) => theme.metrics.fontSize.medium};
  padding-bottom: 5px;
  padding-right: 20px;
  width: ${({ width }) => width ?? '252px'};

  :focus {
    border-bottom: 1px solid ${({ theme }) => theme.colors.input.focus};
  }

  ${({ isInvalid }) =>
    isInvalid &&
    css`
      border-bottom: 1px solid ${({ theme }) => theme.colors.input.error};
      color: ${({ theme }) => theme.colors.input.error};
      :focus {
        border-bottom: 1px solid ${({ theme }) => theme.colors.input.error};
      }
    `};
`;

const Wrapper = styled.div`
  position: relative;
`;

const Label = styled.label<LabelProps>`
  color: ${({ theme }) => theme.colors.input.label};
  position: absolute;
  cursor: text;
  font-size: ${({ theme }) => theme.metrics.fontSize.medium};
  transition: top 0.3s, font-size 0.3s;

  ${({ isFocused }) =>
    isFocused &&
    css`
      font-size: ${({ theme }) => theme.metrics.fontSize.small};
      color: ${({ theme }) => theme.colors.input.active};
      top: -20px;
    `};
`;

const EyeIcon = styled(Icon)`
  position: absolute;
  right: 0;
`;

const Error = styled.span<InputProps>`
  visibility: hidden;
  margin-top: 5px;
  color: ${({ theme }) => theme.colors.input.error};
  font-size: ${({ theme }) => theme.metrics.fontSize.small};
  min-height: 14px;

  ${({ isInvalid }) =>
    isInvalid &&
    css`
      visibility: visible;
    `};
`;

export default { Label, Input, Wrapper, EyeIcon, Container, Error };
