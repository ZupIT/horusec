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
import { Select as SelectComponent } from 'components';

interface LoadingWrapperProps {
  isLoading: boolean;
}

interface TagProps {
  color: string;
}

const Wrapper = styled.div`
  width: 100%;
  padding: 35px 40px 10px 35px;
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

const Column = styled.span`
  text-align: left;
  font-size: ${({ theme }) => theme.metrics.fontSize.small};
  color: ${({ theme }) => theme.colors.dataTable.column.text};
  font-weight: normal;
  width: 100%;
  display: block;
  margin-right: 20px;

  &:nth-child(1) {
    max-width: 250px;
  }

  &:nth-child(2) {
    max-width: 580px;
    margin-right: -10px;
  }

  &:nth-child(3) {
    max-width: 130px;
    padding-left: 25px;
  }

  &:nth-child(4) {
    margin-right: 0px;
    margin-left: 15px;
  }

  &:nth-child(5) {
    max-width: 30px;
    margin-right: 40px;
  }
`;

const Row = styled.div`
  background-color: ${({ theme }) => theme.colors.dataTable.row.background};
  margin-bottom: 4px;
  border-radius: 4px;
  padding: 10px 20px;
  display: flex;
  flex-direction: row;
  position: relative;
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
    max-width: 250px;
  }

  &:nth-child(2) {
    max-width: 580px;
  }

  &:nth-child(3) {
    max-width: 130px;
  }

  &:nth-child(5) {
    max-width: 30px;
    display: flex;
    align-items: center;
    justify-content: center;

    i {
      cursor: pointer;
    }
  }

  &.center {
    display: flex;
    align-items: center;
  }

  .select-type {
    position: absolute !important;
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

const LoadingWrapper = styled.div<LoadingWrapperProps>`
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100%;
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

const EmptyText = styled.span`
  color: ${({ theme }) => theme.colors.dataTable.column.text};
  font-size: ${({ theme }) => theme.metrics.fontSize.medium};
  text-align: center;
  display: block;
  line-height: 170px;
`;

const Select = styled(SelectComponent)`
  margin-right: 15px;
`;

const Tag = styled.span<TagProps>`
  display: block;
  text-align: center;
  text-transform: uppercase;
  height: 23px;
  line-height: 25px;
  width: 84px;
  border-radius: 64px;

  ${({ color }) => css`
    background-color: ${color};
  `};
`;

export default {
  Wrapper,
  Tag,
  Select,
  Options,
  Content,
  Title,
  Table,
  Head,
  Row,
  Cell,
  Body,
  Column,
  LoadingWrapper,
  EmptyText,
};
