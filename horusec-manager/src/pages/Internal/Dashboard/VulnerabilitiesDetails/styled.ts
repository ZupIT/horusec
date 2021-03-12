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

interface LoadingWrapperProps {
  isLoading: boolean;
}

const Wrapper = styled.div`
  background-color: ${({ theme }) => theme.colors.dataTable.backgorund};
  border-radius: 4px;
  height: auto;
  width: 100%;
  padding: 18px 15px 0px 15px;
  position: relative;
`;

const LoadingWrapper = styled.div<LoadingWrapperProps>`
  display: flex;
  justify-content: center;
  align-items: center;
  height: calc(100% - 60px);
  position: absolute;
  width: 100%;
  left: 0;
  background-color: ${({ theme }) => theme.colors.background.secundary};
  z-index: 2;
  visibility: hidden;

  ${({ isLoading }) =>
    isLoading &&
    css`
      visibility: visible;
    `};
`;

const Title = styled.h4`
  color: ${({ theme }) => theme.colors.dataTable.title};
  font-size: ${({ theme }) => theme.metrics.fontSize.xlarge};
  border-radius: 4px;
  padding: 0 10px 0px 10px;
  font-weight: normal;
  display: block;
  min-height: 60px;
`;

const Table = styled.div``;

const Head = styled.div`
  display: flex;
  flex-direction: row;
  padding: 0px 20px;
`;

const Column = styled.span`
  text-align: left;
  font-size: ${({ theme }) => theme.metrics.fontSize.small};
  color: ${({ theme }) => theme.colors.dataTable.column.text};
  font-weight: normal;
  width: 100%;
  display: block;
  margin-right: 20px;

  &:nth-child(1),
  &:nth-child(2),
  &:nth-child(6) {
    max-width: 100px;
  }
`;

const Row = styled.div`
  background-color: ${({ theme }) => theme.colors.dataTable.row.background};
  margin-bottom: 4px;
  border-radius: 4px;
  padding: 15px 20px;
  display: flex;
  flex-direction: row;
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

  &:nth-child(1),
  &:nth-child(2),
  &:nth-child(6) {
    max-width: 100px;
  }
`;

const Body = styled.div`
  overflow-y: scroll;
  height: 220px;
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

const EmptyText = styled.span`
  color: ${({ theme }) => theme.colors.dataTable.column.text};
  font-size: ${({ theme }) => theme.metrics.fontSize.medium};
  text-align: center;
  display: block;
  line-height: 170px;
`;

const Pagination = styled.div`
  margin-top: 10px;
  display: flex;
  align-items: center;
  justify-content: flex-end;
`;

const Button = styled.button`
  background: none;
  border: none;
  outline: none;
  cursor: pointer;
  color: ${({ theme }) => theme.colors.dataTable.column.text};

  :hover {
    transform: scale(1.2);
  }
`;

const CurrentPage = styled.span`
  color: ${({ theme }) => theme.colors.dataTable.column.text};
  margin: 0px 10px;
`;

export default {
  Wrapper,
  Title,
  LoadingWrapper,
  Table,
  Head,
  Row,
  Cell,
  Body,
  Column,
  EmptyText,
  Pagination,
  Button,
  CurrentPage,
};
