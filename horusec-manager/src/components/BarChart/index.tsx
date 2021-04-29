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
import { generateRandomColor } from 'helpers/colors';
import { BarCharRow } from 'helpers/interfaces/BarChartRow';
import { range } from 'lodash';
import { useTranslation } from 'react-i18next';
import { Icon } from 'components';

interface BarChartProps {
  data: BarCharRow[];
  title: string;
  isLoading: boolean;
  ariaLabel?: string;
  onClickRow?: (row: BarCharRow) => any;
  onClickBack?: () => any;
  showBackOption?: boolean;
}

const BarChart: React.FC<BarChartProps> = ({
  data,
  isLoading,
  title,
  ariaLabel,
  onClickRow,
  onClickBack,
  showBackOption,
}) => {
  const { t } = useTranslation();

  const calculatePercentageOfBar = (value: number) => {
    const total = data.reduce((a, b) => {
      return { legend: null, value: a.value + b.value };
    });
    return `${(value * 100) / total.value}%`;
  };

  const renderRow = ({ value, legend, color }: BarCharRow) => (
    <Styled.Row key={legend} onClick={() => onClickRow({ value, legend })}>
      <Styled.Value>{value}</Styled.Value>
      <Styled.Bar
        color={color || generateRandomColor()}
        size={calculatePercentageOfBar(value)}
      />
      <Styled.Legend>{legend}</Styled.Legend>
    </Styled.Row>
  );

  const renderLoading = (index: number) => (
    <Styled.Row isLoading key={index}>
      <Styled.Value isLoading />
      <Styled.Bar isLoading size="100%" />
      <Styled.Legend isLoading />
    </Styled.Row>
  );

  return (
    <Styled.Wrapper tabIndex={0} aria-label={ariaLabel}>
      <Styled.Header>
        <Styled.Title>{title}</Styled.Title>

        {showBackOption ? (
          <Styled.BackWrapper onClick={onClickBack}>
            <Icon name="left-arrow" size="20px" />

            <Styled.Back>{t('GENERAL.BACK')}</Styled.Back>
          </Styled.BackWrapper>
        ) : null}
      </Styled.Header>

      <Styled.WrapperChart>
        {data.length <= 0 ? (
          <Styled.Empty>{t('DASHBOARD_SCREEN.CHART_NO_DATA')}</Styled.Empty>
        ) : null}

        {!isLoading
          ? data.map((item) => renderRow(item))
          : range(4).map((_, i) => renderLoading(i))}
      </Styled.WrapperChart>
    </Styled.Wrapper>
  );
};

export default BarChart;
