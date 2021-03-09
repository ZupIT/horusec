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
import datepicker from 'react-datepicker';
import 'react-datepicker/dist/react-datepicker.css';

interface WrapperProps {
  disabled?: boolean;
}

const DatePicker = styled(datepicker)``;

const Wrapper = styled.div<WrapperProps>`
  display: flex;
  flex-direction: column;

  ${({ disabled }) =>
    disabled &&
    css`
      opacity: 0.5;
    `};
`;

const Title = styled.span`
  font-size: ${({ theme }) => theme.metrics.fontSize.small};
  color: ${({ theme }) => theme.colors.datePicker.title};
  margin-bottom: 4px;
`;

const Container = styled.div`
  border-bottom: 1px ${({ theme }) => theme.colors.datePicker.border} solid;
  display: flex;
  align-items: center;
  padding-bottom: 3px;
`;

interface InputProps {
  isInvalid?: boolean;
}

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

export default {
  DatePicker,
  Wrapper,
  Title,
  Container,
  Error,
};
