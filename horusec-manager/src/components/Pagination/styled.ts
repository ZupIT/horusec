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

interface ListItemProps {
  isVisible: boolean;
}

const Wrapper = styled.div`
  display: flex;
  flex-direction: row;
  justify-content: flex-end;
  align-items: center;
  padding: 10px;
  height: 80px;
`;

const ArrowIcon = styled(Icon)`
  :hover {
    cursor: pointer;
    transform: scale(1.3);
  }
`;

const Next = styled(ArrowIcon)``;

const Previous = styled(ArrowIcon)`
  margin-right: 30px;
`;

const Text = styled.span`
  color: ${({ theme }) => theme.colors.text.primary};
  font-size: ${({ theme }) => theme.metrics.fontSize.medium};
  margin: 0px 2px;
`;

const PagesWrapper = styled.div`
  display: block;
  margin-right: 30px;
`;

const ItemWrapper = styled.div`
  cursor: pointer;
  display: flex;
  align-items: center;
  margin-right: 30px;
  position: relative;
`;

const ListItems = styled.ul<ListItemProps>`
  background-color: ${({ theme }) => theme.colors.background.highlight};
  width: 80px;
  position: absolute;
  top: 20px;
  right: 0;
  z-index: 3;
  height: 0;
  opacity: 0;
  transition: all 0.5s;
  visibility: hidden;

  ${({ isVisible }) =>
    isVisible &&
    css`
      height: 80px;
      opacity: 1;
      visibility: visible;
    `};
`;

const Item = styled.li`
  list-style: none;
  color: ${({ theme }) => theme.colors.text.primary};
  font-size: ${({ theme }) => theme.metrics.fontSize.medium};
  padding: 5px;
  cursor: pointer;

  :hover {
    background-color: ${({ theme }) => theme.colors.background.overlap};
  }
`;

export default {
  Wrapper,
  Previous,
  Next,
  Text,
  PagesWrapper,
  ItemWrapper,
  ListItems,
  Item,
};
