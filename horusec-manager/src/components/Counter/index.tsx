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

import React from 'react';
import Styled from './styled';
import { Icon } from 'components';
import { useTranslation } from 'react-i18next';

interface CounterProps {
  title: string;
  value: number;
  isLoading?: boolean;
}

const Counter: React.FC<CounterProps> = ({ title, value, isLoading }) => {
  const { t } = useTranslation();

  const renderContent = () => {
    return value ? (
      <Styled.Count>{value}</Styled.Count>
    ) : (
      <Styled.EmptyText>{t('DASHBOARD_SCREEN.CHART_NO_DATA')}</Styled.EmptyText>
    );
  };

  return (
    <Styled.Wrapper tabIndex={0}>
      <Styled.Title tabIndex={-1}>{title}</Styled.Title>

      <Styled.Container>
        {isLoading ? <Icon name="loading" size="100px" /> : renderContent()}
      </Styled.Container>
    </Styled.Wrapper>
  );
};

export default Counter;
