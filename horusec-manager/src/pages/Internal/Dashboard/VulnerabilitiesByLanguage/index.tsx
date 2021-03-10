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

import React, { useState, useEffect, useCallback } from 'react';
import ReactApexChart from 'react-apexcharts';
import { ApexOptions } from 'apexcharts';
import Styled from './styled';
import { useTranslation } from 'react-i18next';
import { useTheme } from 'styled-components';
import { Icon } from 'components';
import { FilterValues } from 'helpers/interfaces/FilterValues';
import analyticService from 'services/analytic';
import { get } from 'lodash';
import { AxiosResponse } from 'axios';

interface Props {
  filters?: FilterValues;
}

const VulnerabilitiesByLanguage: React.FC<Props> = ({ filters }) => {
  const { t } = useTranslation();
  const { colors } = useTheme();

  const [isLoading, setLoading] = useState(true);

  const [chartValues, setChartValues] = useState<number[]>([]);
  const [chartLabels, setChartLabels] = useState<string[]>([]);
  const [chartColors, setChartColors] = useState<string[]>([]);

  const options: ApexOptions = {
    markers: {
      size: 0,
    },
    noData: {
      text: t('DASHBOARD_SCREEN.CHART_NO_DATA'),
      style: {
        color: colors.chart.legend,
      },
    },
    chart: {
      type: 'donut',
      fontFamily: 'SFRegular',
      animations: {
        enabled: true,
      },
      toolbar: {
        show: false,
      },
    },
    legend: {
      position: 'top',
      horizontalAlign: 'left',
      labels: {
        colors: colors.chart.legend,
      },
    },
    dataLabels: {
      enabled: false,
    },
    stroke: {
      show: false,
    },
    plotOptions: {
      pie: {
        donut: {
          size: '35px',
        },
      },
    },
  };

  const formatData = useCallback(
    (data: [{ language: string; total: number }]) => {
      const itemColors: string[] = [];
      const labels: string[] = [];
      const values: number[] = [];

      data.forEach((item) => {
        labels.push(item.language);
        values.push(item.total);
        itemColors.push(
          get(
            colors.languages,
            item.language.toUpperCase(),
            colors.languages.UNKNOWN
          )
        );
      });

      setChartColors(itemColors);
      setChartLabels(labels);
      setChartValues(values);
    },
    [colors]
  );

  useEffect(() => {
    let isCancelled = false;
    if (filters) {
      setLoading(true);

      analyticService
        .getVulnerabilitiesByLanguage(filters)
        .then((result: AxiosResponse) => {
          if (!isCancelled) {
            formatData(result.data.content);
          }
        })
        .finally(() => {
          if (!isCancelled) {
            setLoading(false);
          }
        });
    }

    return () => {
      isCancelled = true;
    };
  }, [filters, formatData]);

  return (
    <div className="block max-space">
      <Styled.Wrapper>
        <Styled.Title>
          {t('DASHBOARD_SCREEN.VULNERABILITIES_BY_LANG')}
        </Styled.Title>

        {isLoading ? (
          <Styled.LoadingWrapper>
            <Icon name="loading" size="200px" className="loading" />
          </Styled.LoadingWrapper>
        ) : (
          <ReactApexChart
            height={250}
            width="100%"
            series={chartValues}
            options={{ ...options, colors: chartColors, labels: chartLabels }}
            type="donut"
          />
        )}
      </Styled.Wrapper>
    </div>
  );
};

export default VulnerabilitiesByLanguage;
