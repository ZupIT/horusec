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
import 'react-datepicker/dist/react-datepicker.css';

interface OptionsListProps {
  isOpen: boolean;
  rounded: boolean;
  width: string;
  height: string;
}

interface WrapperProps {
  disabled: boolean;
  rounded: boolean;
  width: string;
  height?: string;
  backgroundColor?: string;
}

interface OptionItem {
  rounded: boolean;
}

const Wrapper = styled.div<WrapperProps>`
  display: flex;
  flex-direction: column;
`;

const Title = styled.span`
  font-size: ${({ theme }) => theme.metrics.fontSize.small};
  color: ${({ theme }) => theme.colors.select.title};
  margin-bottom: 10px;
`;

interface ContainerInterface {
  width: string;
}

const Container = styled.div<ContainerInterface>`
  width: ${({ width }) => width || '100%'};
  transition: all 1s;
`;

const Select = styled.div`
  appearance: none;
  border: none;
  background: none;
  outline: none;
  width: 150px;
  font-size: ${({ theme }) => theme.metrics.fontSize.medium};
  color: ${({ theme }) => theme.colors.select.text};
`;

const OptionsList = styled.div<OptionsListProps>`
  box-shadow: 0 2px 7px 0 rgba(0, 0, 0, 0.5);
  position: absolute;
  top: 28px;
  left: 0;
  background-color: ${({ theme }) => theme.colors.select.background};
  border-bottom-left-radius: 4px;
  border-bottom-right-radius: 4px;
  width: ${({ width }) => (width ? width : '100%')};
  overflow-y: auto;
  transition: all 0.5s;
  height: 0;
  z-index: 5;

  ${({ isOpen, height }) =>
    isOpen &&
    css`
      height: ${height ? height : '64px'};
    `};

  ${({ rounded }) =>
    rounded &&
    css`
      top: 33px !important;
    `};

  ::-webkit-scrollbar {
    width: 5px;
  }

  ::-webkit-scrollbar-thumb {
    background: ${({ theme }) => theme.colors.scrollbar};
    border-radius: 2px;
  }

  ::-webkit-scrollbar-track {
    background-color: ${({ theme }) => theme.colors.select.background};
  }
`;

const OptionItem = styled.div<OptionItem>`
  font-size: ${({ theme }) => theme.metrics.fontSize.small};
  line-height: ${({ theme }) => theme.metrics.fontSize.small} !important;
  color: ${({ theme }) => theme.colors.select.text};
  cursor: pointer;
  padding: 10px;

  :hover {
    background-color: ${({ theme }) => theme.colors.select.hover};
  }
`;

const FixedOptionItem = styled(OptionItem)`
  width: 100%;
  margin-top: 15px;
  color: ${({ theme }) => theme.colors.select.highlight};
  text-decoration: underline;
`;

const CurrentValue = styled.input`
  font-size: ${({ theme }) => theme.metrics.fontSize.medium};
  color: ${({ theme }) => theme.colors.select.text};
  display: block;
  width: 100%;
  background: none;
  border: none;
  outline: none;
  cursor: pointer;
`;

export default {
  CurrentValue,
  Select,
  OptionsList,
  OptionItem,
  Wrapper,
  Title,
  Container,
  FixedOptionItem,
};
