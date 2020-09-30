import React, { useState, useEffect } from 'react';
import ReactApexChart from 'react-apexcharts';
import { ApexOptions } from 'apexcharts';
import Styled from './styled';
import { useTranslation } from 'react-i18next';
import { useTheme } from 'styled-components';
import { Icon } from 'components';
import { FilterValues } from 'helpers/interfaces/FilterValues';
import analyticService from 'services/analytic';
import { ChartBarStacked } from 'helpers/interfaces/ChartData';
import { formatChartStacked } from 'helpers/formatters/chartData';

interface Props {
  filters?: FilterValues;
}

const VulnerabilitiesByDeveloper: React.FC<Props> = ({ filters }) => {
  const { t } = useTranslation();
  const { colors } = useTheme();

  const [isLoading, setLoading] = useState(true);
  const [chartData, setChartData] = useState<ChartBarStacked>({
    categories: [],
    series: [],
  });

  const options: ApexOptions = {
    markers: {
      size: 0,
    },
    colors: Object.values(colors.vulnerabilities),
    noData: {
      text: t('CHART_NO_DATA'),
      style: {
        color: colors.chart.legend,
      },
    },
    legend: {
      position: 'top',
      horizontalAlign: 'left',
      offsetX: 40,
      labels: {
        colors: colors.chart.legend,
      },
    },
    chart: {
      fontFamily: 'SFRegular',
      stacked: true,
      animations: {
        enabled: true,
      },
      toolbar: {
        show: false,
      },
    },
    plotOptions: {
      bar: {
        horizontal: true,
      },
    },
    xaxis: {
      labels: {
        style: {
          colors: colors.chart.legend,
        },
      },
      categories: [],
    },
    yaxis: {
      title: {
        text: undefined,
      },
      labels: {
        style: {
          colors: colors.chart.legend,
        },
      },
    },
  };

  useEffect(() => {
    if (filters) {
      setLoading(true);

      analyticService
        .getVulnerabilitiesByDeveloper(filters)
        .then((result) => {
          setChartData(formatChartStacked(result.data.content, 'developer'));
        })
        .finally(() => {
          setLoading(false);
        });
    }
  }, [filters]);

  return (
    <div className="block max-space">
      <Styled.Wrapper>
        <Styled.Title>{t('VULNERABILITIES_BY_DEV')}</Styled.Title>

        <Styled.LoadingWrapper isLoading={isLoading}>
          <Icon name="loading" size="200px" className="loading" />
        </Styled.LoadingWrapper>

        <ReactApexChart
          height={250}
          width="100%"
          options={{
            ...options,
            xaxis: { ...options.xaxis, categories: chartData.categories },
          }}
          series={chartData.series}
          type="bar"
        />
      </Styled.Wrapper>
    </div>
  );
};

export default VulnerabilitiesByDeveloper;
