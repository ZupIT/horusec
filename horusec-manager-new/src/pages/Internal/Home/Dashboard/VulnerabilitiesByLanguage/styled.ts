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
  background-color: ${({ theme }) => theme.colors.background.secundary};
  border-radius: 4px;
  height: 330px;
  width: 100%;
  padding: 0 15px 10px 15px;
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
  color: ${({ theme }) => theme.colors.chart.title};
  font-size: ${({ theme }) => theme.metrics.fontSize.xlarge};
  border-radius: 4px;
  padding: 18px 10px 0px 10px;
  font-weight: normal;
  display: block;
  min-height: 60px;
`;

export default { Wrapper, Title, LoadingWrapper };
