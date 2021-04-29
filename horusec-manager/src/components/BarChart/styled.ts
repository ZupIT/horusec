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

import styled, { keyframes, css } from 'styled-components';

interface BarProps {
  color?: string;
  size: string;
  isLoading?: boolean;
}

interface LoadingProps {
  isLoading?: boolean;
}

const Wrapper = styled.div`
  background-color: ${({ theme }) => theme.colors.background.secundary};
  border-radius: 4px;
  width: 100%;
  min-width: 170px;
  height: auto;
  min-height: 330px;
  display: flex;
  flex-direction: column;
  padding: 25px 50px;
`;

const Header = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 30px;
`;

const Title = styled.h2`
  color: ${({ theme }) => theme.colors.chart.title};
  font-size: ${({ theme }) => theme.metrics.fontSize.xlarge};
  border-radius: 4px;
  font-weight: normal;
  display: block;
`;

const BackWrapper = styled.span`
  display: flex;
  align-items: center;
  cursor: pointer;

  :hover {
    transform: scale(1.2);
  }
`;

const Back = styled.span`
  display: block;
  color: ${({ theme }) => theme.colors.chart.title};
  margin-left: 5px;
`;

const Empty = styled.h2`
  color: ${({ theme }) => theme.colors.dataTable.column.text};
  font-size: ${({ theme }) => theme.metrics.fontSize.large};
  font-weight: normal;
  text-align: center;
  display: block;
  line-height: 170px;
`;

const WrapperChart = styled.ul`
  list-style: none;
`;

const Row = styled.li<LoadingProps>`
  width: 100%;
  display: flex;
  align-items: center;
  margin-top: 10px;
  position: relative;

  ${({ isLoading, theme }) =>
    isLoading &&
    `
    ::before {
      content: '';
      width: 100%;
      height: 25px;
      background: transparent;
      background-image: linear-gradient(
        to right,
        #2c2c2e 0%,
        #2c2c2e 10%,
        #2c2c2e 40%,
        #2c2c2e 100%
      );
      background-repeat: no-repeat;
      background-size: 100% 50px;
      display: inline-block;
      position: absolute;
      z-index: 1;

      animation-duration: 1.5s;
      animation-fill-mode: forwards;
      animation-iteration-count: infinite;
      animation-name: placeholderShimmer;
      animation-timing-function: linear;

      @keyframes placeholderShimmer {
        0% {
          background-position: -900px 0;
        }
        100% {
          background-position: 900px 0;
        }
      }
    }
  `}
`;

const Value = styled.span<LoadingProps>`
  color: ${({ theme }) => theme.colors.chart.legend};
  margin-right: 15px;
  display: block;
  min-width: 20px;
  text-align: start;

  ${({ isLoading, theme }) =>
    isLoading &&
    `
    background-color: ${theme.colors.chart.background};
    height: ${theme.metrics.fontSize.medium}
  `}
`;

const resizeBar = (perc: string) => keyframes`
  from {
    width: 0px;
  }
  to {
    width: ${perc};
  }
`;

const Bar = styled.div<BarProps>`
  display: block;
  width: 100%;
  height: 25px;
  background-color: ${({ theme }) => theme.colors.chart.background};
  position: relative;
  cursor: pointer;

  :hover {
    box-shadow: 0 0 6px rgba(33, 33, 33, 0.8);
  }

  ${({ isLoading, theme }) =>
    isLoading &&
    `
    cursor: default;
    background-color: ${theme.colors.chart.background};

    :hover {
      box-shadow: none;
    }
  `}

  ::before {
    content: '';
    display: block;
    position: absolute;
    top: 0;
    left: 0;
    height: 100%;
    background-color: ${({ color }) => color};
    width: ${({ size }) => size};
    animation: ${({ size }) => css`
      ${resizeBar(size)} 1s ease-in-out
    `};
  }
`;

const Legend = styled.span<LoadingProps>`
  color: ${({ theme }) => theme.colors.chart.legend};
  margin-left: 20px;
  min-width: 200px;
  text-align: start;
  white-space: nowrap;
  overflow: auto;
  text-overflow: ellipsis;

  ${({ isLoading, theme }) =>
    isLoading &&
    `
    background-color: ${theme.colors.chart.background};
    height: ${theme.metrics.fontSize.medium}
  `}
`;

export default {
  Wrapper,
  Title,
  WrapperChart,
  Bar,
  Row,
  Legend,
  Value,
  Empty,
  Header,
  Back,
  BackWrapper,
};
