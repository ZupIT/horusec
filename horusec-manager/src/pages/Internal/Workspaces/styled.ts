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
  padding: 35px;
  width: 100%;
`;

const Options = styled.div`
  background-color: ${({ theme }) => theme.colors.background.secundary};
  border-radius: 4px;
  padding: 22px;
  display: flex;
  align-items: center;
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

const Table = styled.div`
  margin-top: 30px;
`;

const Head = styled.div`
  display: flex;
  flex-direction: row;
  padding: 0px 20px;
`;

const Row = styled.div`
  background-color: ${({ theme }) => theme.colors.dataTable.row.background};
  margin-bottom: 4px;
  border-radius: 4px;
  padding: 10px 20px;
  display: flex;
  flex-direction: row;
`;

const Column = styled.span`
  text-align: left;
  font-size: ${({ theme }) => theme.metrics.fontSize.small};
  color: ${({ theme }) => theme.colors.dataTable.column.text};
  font-weight: normal;
  width: 100%;
  display: block;
  margin-right: 20px;

  &:nth-child(1) {
    max-width: 160px;
  }

  &:nth-child(2) {
    max-width: 100px;
  }

  &:nth-child(3) {
    max-width: 180px;
  }
`;

const Cell = styled.span`
  text-align: left;
  font-size: ${({ theme }) => theme.metrics.fontSize.small};
  color: ${({ theme }) => theme.colors.dataTable.row.text};
  font-weight: normal;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  display: block;
  width: 100%;
  margin-right: 20px;
  line-height: 30px;
  padding: 2px;

  &:nth-child(1) {
    max-width: 160px;
  }

  &:nth-child(2) {
    max-width: 100px;
  }

  &:nth-child(3) {
    max-width: 180px;
  }

  &.row {
    display: flex;
    flex-direction: row;

    button {
      margin-right: 10px;
    }
  }
`;

const Body = styled.div`
  overflow-y: scroll;
  max-height: 400px;
  min-height: 180px;
  margin-top: 10px;
  padding-right: 10px;

  ::-webkit-scrollbar {
    width: 6px;
  }

  ::-webkit-scrollbar-thumb {
    background: ${({ theme }) => theme.colors.scrollbar};
    border-radius: 4px;
  }
`;

export default {
  Wrapper,
  Options,
  Content,
  Title,
  Table,
  Head,
  Row,
  Cell,
  Body,
  Column,
};
