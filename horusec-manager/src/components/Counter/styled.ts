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

const Wrapper = styled.div`
  background-color: ${({ theme }) => theme.colors.background.secundary};
  border-radius: 4px;
  width: 100%;
  min-width: 170px;
  height: 300px;
  display: flex;
  flex-direction: column;
`;

const EmptyText = styled.span`
  color: ${({ theme }) => theme.colors.dataTable.column.text};
  font-size: ${({ theme }) => theme.metrics.fontSize.large};
  text-align: center;
  display: block;
  line-height: 170px;
`;

const Title = styled.h2`
  color: ${({ theme }) => theme.colors.chart.title};
  font-size: ${({ theme }) => theme.metrics.fontSize.xlarge};
  border-radius: 4px;
  padding: 18px 10px 0px 10px;
  font-weight: normal;
  display: block;
  min-height: 60px;
`;

const Container = styled.div`
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
`;

const Count = styled.span`
  color: ${({ theme }) => theme.colors.chart.legend};
  font-size: ${({ theme }) => theme.metrics.fontSize.big};
  text-align: end;
  font-weight: normal;
  display: block;
`;

export default { Wrapper, Title, Count, Container, EmptyText };
