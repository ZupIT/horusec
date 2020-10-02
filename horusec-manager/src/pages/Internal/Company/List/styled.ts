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

interface SettingsProps {
  isVisible: boolean;
}

interface ItemProps {
  selected: boolean;
}

const Title = styled.h1`
  font-weight: normal;
  font-size: ${({ theme }) => theme.metrics.fontSize.xxlarge};
  color: ${({ theme }) => theme.colors.text.primary};
  align-self: flex-start;
`;

const OptionsWrapper = styled.div`
  display: flex;
  justify-content: flex-end;
  width: 100%;
  margin: 10px 0;

  @media (max-width: 425px) {
    margin: 20px 0;
  }
`;

const AddCompanyBtn = styled.button`
  cursor: pointer;
  background: none;
  outline: none;
  padding: 7px 13px;
  border-radius: 30px;
  font-size: ${({ theme }) => theme.metrics.fontSize.small};
  border: 1px solid ${({ theme }) => theme.colors.optionButton.text};
  display: flex;
  align-items: center;

  :hover {
    transform: scale(1.03);
  }
`;

const TextBtn = styled.span`
  display: block;
  color: ${({ theme }) => theme.colors.optionButton.text};
  margin-left: 8px;

  @media (max-width: 425px) {
    margin-left: 3px;
  }
`;

const SearchWrapper = styled.div`
  padding: 7px 13px;
  border-radius: 30px;
  border: 1px solid ${({ theme }) => theme.colors.optionButton.text};
  display: flex;
  align-items: center;
  width: 98px;
  margin-left: 10px;
`;

const SearchInput = styled.input`
  border: none;
  background: none;
  outline: none;
  width: 100%;
  font-size: ${({ theme }) => theme.metrics.fontSize.medium};
  color: ${({ theme }) => theme.colors.input.text};
  margin-right: 5px;
`;

const ListWrapper = styled.div`
  border-radius: 4px;
  background-color: ${({ theme }) => theme.colors.background.highlight};
  padding: 18px 8px 18px 18px;
  position: relative;
`;

const List = styled.ul`
  max-height: 138px;
  min-height: 90px;
  overflow-y: scroll;
  padding-right: 10px;

  ::-webkit-scrollbar {
    width: 10px;
  }

  ::-webkit-scrollbar-thumb {
    background: ${({ theme }) => theme.colors.scrollbar};
    border-radius: 4px;
  }
`;

const Item = styled.li<ItemProps>`
  background-color: ${({ theme }) => theme.colors.background.secundary};
  list-style: none;
  border-radius: 4px;
  transition: background-color 0.7s;
  display: flex;
  margin-top: 2px;

  ${({ selected }) =>
    selected &&
    css`
      background-color: ${({ theme }) => theme.colors.background.overlap};
    `};

  :hover {
    cursor: pointer;
    background-color: ${({ theme }) => theme.colors.background.overlap};
  }
`;

const ItemText = styled.span`
  color: ${({ theme }) => theme.colors.input.text};
  font-size: ${({ theme }) => theme.metrics.fontSize.medium};
  width: 100%;
  display: block;
  text-overflow: ellipsis;
  white-space: nowrap;
  overflow: hidden;
  padding-right: 10px;
  padding: 16px 5px 14px 14px;
`;

const SettingsIcon = styled(Icon)`
  cursor: pointer;
  align-self: flex-start;
  margin: 15px 25px;

  :hover {
    transform: scale(1.3);
  }
`;

const Settings = styled.ul<SettingsProps>`
  position: absolute;
  z-index: -1;
  right: 0px;
  top: 30%;
  background-color: ${({ theme }) => theme.colors.background.highlight};
  box-shadow: 0 2px 10px 0 rgba(0, 0, 0, 0.32);
  border-radius: 2px;
  min-width: 145px;
  opacity: 0;
  transition: all 0.5s;
  height: 0px;

  ${({ isVisible }) =>
    isVisible &&
    css`
      height: 102px;
      opacity: 1;
      z-index: 3;
    `};
`;

const SettingsItem = styled.li`
  font-size: ${({ theme }) => theme.metrics.fontSize.small};
  color: ${({ theme }) => theme.colors.input.text};
  list-style: none;
  padding: 10px;

  :hover {
    background-color: ${({ theme }) => theme.colors.background.overlap};
  }
`;

const NoItem = styled.li`
  color: ${({ theme }) => theme.colors.input.text};
  font-size: ${({ theme }) => theme.metrics.fontSize.medium};
  background-color: ${({ theme }) => theme.colors.background.secundary};
  list-style: none;
  padding: 16px 5px 14px 14px;
  border-radius: 4px;
`;

const Shimmer = styled.li`
  list-style: none;
  background-color: ${({ theme }) => theme.colors.background.secundary};
  list-style: none;
  padding: 16px 5px 14px 14px;
  border-radius: 4px;

  ::before {
    content: '';
    display: block;
    width: 40%;
    height: 16px;
    animation: shimmer 2s infinite;
    animation-fill-mode: forwards;
    animation-timing-function: linear;
    background-color: ${({ theme }) => theme.colors.background.highlight};
    background-image: linear-gradient(
      to right,
      #3a3a3c 0%,
      #2c2c2e 20%,
      #3a3a3c 40%,
      #3a3a3c 100%
    );
    background-repeat: no-repeat;
    display: inline-block;
    position: relative;

    -webkit-animation-fill-mode: forwards;
    -webkit-animation-timing-function: linear;
  }
`;

export default {
  Title,
  OptionsWrapper,
  AddCompanyBtn,
  TextBtn,
  SearchWrapper,
  SearchInput,
  List,
  NoItem,
  Item,
  SettingsIcon,
  ItemText,
  ListWrapper,
  Settings,
  SettingsItem,
  Shimmer,
};
