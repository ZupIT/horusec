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

interface CheckboxProps {
  isChecked?: boolean;
  disabled?: boolean;
}

const Checkbox = styled.div<CheckboxProps>`
  border: 1px solid ${({ theme }) => theme.colors.checkbox.border};
  border-radius: 4px;
  width: 15px;
  height: 15px;
  cursor: pointer;

  ${({ isChecked }) =>
    isChecked &&
    css`
      border: none;
      background: linear-gradient(
        ${({ theme }) =>
          `90deg, ${theme.colors.checkbox.checked.primary} 0%, ${theme.colors.checkbox.checked.secundary} 100%`}
      );
    `};

  ${({ disabled }) =>
    disabled &&
    css`
      opacity: 0.3;
      cursor: not-allowed;
    `};
`;

export default {
  Checkbox,
};
