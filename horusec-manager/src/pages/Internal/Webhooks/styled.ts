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

interface TagProps {
  color: string;
}

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
`;

const TitleWrapper = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
`;

const Title = styled.h1`
  color: ${({ theme }) => theme.colors.text.secundary};
  font-weight: normal;
  font-size: ${({ theme }) => theme.metrics.fontSize.xlarge};
`;

const Table = styled.div`
  margin-top: 30px;
  position: relative;
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

  &.flex-center {
    display: flex;
    align-items: center;
    justify-content: flex-start;
  }

  &.row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-direction: row;
  }

  &:nth-child(1) {
    max-width: 120px;
    margin: 0;
  }

  &:nth-child(2) {
    max-width: 230px;
  }

  &:nth-child(3) {
    min-width: 270px;
    margin-right: 15px;
  }

  &:nth-child(4) {
    max-width: 100px;
  }

  &:nth-child(5) {
    margin: 0;
    min-width: 190px;
  }
`;

const Column = styled.span`
  text-align: left;
  font-size: ${({ theme }) => theme.metrics.fontSize.small};
  color: ${({ theme }) => theme.colors.dataTable.column.text};
  font-weight: normal;
  width: 100%;
  display: block;
  margin-right: 15px;

  &:nth-child(1) {
    max-width: 120px;
    margin: 0;
  }

  &:nth-child(2) {
    max-width: 230px;
    margin-left: 5px;
  }

  &:nth-child(3) {
    min-width: 270px;
  }

  &:nth-child(4) {
    max-width: 100px;
  }

  &:nth-child(5) {
    min-width: 190px;
    margin-left: 10px;
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
  Options,
  Tag,
  Content,
  Title,
  TitleWrapper,
  Table,
  Head,
  Body,
  Row,
  Column,
  LoadingWrapper,
  EmptyText,
  Cell,
};
