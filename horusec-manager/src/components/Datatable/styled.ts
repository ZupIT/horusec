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

import { Icon } from 'components';
import styled from 'styled-components';

const Wrapper = styled.section`
  max-height: 56vh;
  overflow-y: auto;
  margin-top: 20px;
  padding-right: 10px;
  height: 100vh;

  ::-webkit-scrollbar {
    width: 6px;
  }

  ::-webkit-scrollbar-thumb {
    background: ${({ theme }) => theme.colors.scrollbar};
    border-radius: 4px;
  }
`;

const Content = styled.div`
  margin-top: 25px;
  padding: 25px 15px 10px 25px;
  background-color: ${({ theme }) => theme.colors.background.secundary};
  border-radius: 4px;
  position: relative;
`;

const Title = styled.h1`
  color: ${({ theme }) => theme.colors.text.secundary};
  font-weight: normal;
  font-size: ${({ theme }) => theme.metrics.fontSize.xlarge};
`;

const Table = styled.table<{ isPaginate: boolean; fixed: boolean }>`
  width: 100%;
  border-spacing: 0px 5px;
  table-layout: ${({ fixed }) => (fixed ? 'fixed' : 'auto')};
`;

const Head = styled.tr`
  padding: 0px 20px;
`;

const Column = styled.th`
  text-align: left;
  font-size: ${({ theme }) => theme.metrics.fontSize.small};
  color: ${({ theme }) => theme.colors.dataTable.column.text};
  font-weight: normal;
  padding: 10px 20px;
`;

const Cell = styled.td`
  text-align: left;
  font-size: ${({ theme }) => theme.metrics.fontSize.small};
  color: ${({ theme }) => theme.colors.dataTable.row.text};
  font-weight: normal;
  white-space: nowrap;
  overflow: overlay;
  text-overflow: ellipsis;
  width: 1%;
  padding: 10px 20px;

  & div.row {
    display: flex;
    flex-direction: row;

    button {
      margin-right: 10px;
    }
  }

  &:first-child {
    border-top-left-radius: 5px;
    border-bottom-left-radius: 5px;
  }

  &:last-child {
    border-top-right-radius: 5px;
    border-bottom-right-radius: 5px;
  }
`;

const Row = styled.tr`
  background-color: ${({ theme }) => theme.colors.dataTable.row.background};
  margin-bottom: 4px;
  border-radius: 4px;
  padding: 10px 20px;
`;

const Body = styled.tbody`
  overflow-y: scroll;
  margin-top: 10px;
  padding-right: 10px;
`;

const EmptyText = styled.span`
  color: ${({ theme }) => theme.colors.dataTable.column.text};
  font-size: ${({ theme }) => theme.metrics.fontSize.medium};
  display: flex;
  align-items: center;
  height: 200px;
  justify-content: center;
`;

const LoadingWrapper = styled.div`
  display: flex;
  justify-content: center;
  align-items: center;
  width: 100%;
  height: 56vh;
  background-color: ${({ theme }) => theme.colors.background.secundary};
  z-index: 2;
`;

const ButtonIcon = styled(Icon)`
  position: absolute;
  right: 10px;
  top: 20px;
  cursor: pointer;

  :hover {
    transform: scale(1.2);
  }
`;

export default {
  Wrapper,
  Content,
  Title,
  Body,
  Cell,
  Row,
  Column,
  Head,
  Table,
  EmptyText,
  LoadingWrapper,
  ButtonIcon,
};
