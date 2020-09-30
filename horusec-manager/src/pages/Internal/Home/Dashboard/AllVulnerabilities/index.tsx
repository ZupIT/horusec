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

interface Props {
  filters?: FilterValues;
}

const AllVulnerabilities: React.FC<Props> = ({ filters }) => {
  const { t } = useTranslation();
  const { colors } = useTheme();

  const [isLoading, setLoading] = useState(true);

  const [chartValues, setChartValues] = useState<number[]>([]);
  const [chartLabels, setChartLabels] = useState<string[]>([]);
  const [chartColors, setChartColors] = useState<string[]>([]);

  const options: ApexOptions = {
    noData: {
      text: t('CHART_NO_DATA'),
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
    if (filters) {
      setLoading(true);

      analyticService
        .getAllVulnerabilities(filters)
        .then((result) => {
          formatData(result?.data?.content);
        })
        .finally(() => {
          setLoading(false);
        });
    }
    // eslint-disable-next-line
  }, [filters]);

  return (
    <div className="block max-space">
      <Styled.Wrapper>
        <Styled.Title>{t('ALL_VULNERABILITIES')}</Styled.Title>

        <Styled.LoadingWrapper isLoading={isLoading}>
          <Icon name="loading" size="200px" className="loading" />
        </Styled.LoadingWrapper>

        <ReactApexChart
          height={250}
          width="100%"
          series={chartValues}
          options={{ ...options, colors: chartColors, labels: chartLabels }}
          type="donut"
        />
      </Styled.Wrapper>
    </div>
  );
};

export default AllVulnerabilities;
