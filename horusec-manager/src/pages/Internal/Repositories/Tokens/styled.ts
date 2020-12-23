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

interface LoadingWrapperProps {
  isLoading: boolean;
}

const Background = styled.div`
  width: 100vw;
  height: 100vh;
  position: fixed;
  background-color: ${({ theme }) => theme.colors.dialog.backgroundScreen};
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 3;
  top: 0;
  left: 0;
`;

const Wrapper = styled.div`
  background-color: ${({ theme }) => theme.colors.dialog.background};
  width: 720px;
  padding: 30px 40px;
  border-radius: 4px;
`;

const Header = styled.div`
  display: flex;
  justify-content: space-between;
  margin-bottom: 30px;
`;

const Title = styled.div`
  color: ${({ theme }) => theme.colors.dialog.text};
  font-size: ${({ theme }) => theme.metrics.fontSize.xxlarge};
  line-height: 22px;
`;

const Close = styled(Icon)`
  transition-duration: 0.5s;
  transition-property: transform;

  :hover {
    transform: rotate(90deg);
    -webkit-transform: rotate(90deg);
    cursor: pointer;
  }
`;

const Table = styled.div`
  margin-top: 45px;
  position: relative;
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

  /* &:nth-child(1) {
    max-width: 120px;
  }

  &:nth-child(2) {
    max-width: 400px;
  } */
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

  /* &:nth-child(1) {
    max-width: 120px;
  }

  &:nth-child(2) {
    max-width: 400px;
  } */

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
  max-height: 240px;
  min-height: 80px;
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

export default {
  Background,
  Wrapper,
  Header,
  Title,
  Close,
  EmptyText,
  LoadingWrapper,
  Body,
  Cell,
  Row,
  Column,
  Head,
  Table,
};
