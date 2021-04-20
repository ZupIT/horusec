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

import React, { useState, useEffect } from 'react';
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

const AllVulnerabilities: React.FC<Props> = ({ filters }) => {
  const { t } = useTranslation();
  const { colors, metrics } = useTheme();

  const [isLoading, setLoading] = useState(false);

  const [chartValues, setChartValues] = useState<number[]>([]);
  const [chartLabels, setChartLabels] = useState<string[]>([]);
  const [chartColors, setChartColors] = useState<string[]>([]);

  const options: ApexOptions = {
    noData: {
      text: t('DASHBOARD_SCREEN.CHART_NO_DATA'),
      style: {
        color: colors.chart.legend,
        fontSize: metrics.fontSize.large,
      },
    },
    chart: {
      type: 'donut',
      fontFamily: 'SFRegular',
      animations: {
        enabled: true,
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
      enabled: true,
      style: {
        fontSize: metrics.fontSize.small,
      },
    },
    stroke: {
      show: false,
    },
    plotOptions: {
      pie: {
        donut: {
          size: '25px',
        },
      },
    },
  };

  const formatData = (data: [{ severity: string; total: number }]) => {
    const itemColors: string[] = [];
    const labels: string[] = [];
    const values: number[] = [];

    data.forEach((item) => {
      labels.push(item.severity);
      values.push(item.total);
      itemColors.push(
        get(
          colors.vulnerabilities,
          item.severity,
          colors.vulnerabilities.DEFAULT
        )
      );
    });

    setChartColors(itemColors);
    setChartLabels(labels);
    setChartValues(values);
  };

  useEffect(() => {
    let isCancelled = false;
    if (filters) {
      setLoading(true);

      analyticService
        .getAllVulnerabilities(filters)
        .then((result: AxiosResponse) => {
          if (!isCancelled) {
            formatData(result.data?.content);
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
    // eslint-disable-next-line
  }, [filters]);

  return (
    <div className="block max-space">
      <Styled.Wrapper tabIndex={0}>
        <Styled.Title>{t('DASHBOARD_SCREEN.ALL_VULNERABILITIES')}</Styled.Title>

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

export default AllVulnerabilities;
