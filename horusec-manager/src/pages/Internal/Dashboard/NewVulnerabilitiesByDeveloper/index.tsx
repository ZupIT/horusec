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
import { useTranslation } from 'react-i18next';
import { FilterValues } from 'helpers/interfaces/FilterValues';
import analyticService from 'services/analytic';
import { AxiosResponse } from 'axios';
import { BarCharRow } from 'helpers/interfaces/BarChartRow';
import { BarChart } from 'components';
import { get } from 'lodash';
import { useTheme } from 'styled-components';

interface Props {
  filters?: FilterValues;
}

const NewVulnerabilitiesByDeveloper: React.FC<Props> = ({ filters }) => {
  const { t } = useTranslation();
  const { colors } = useTheme();

  const [isLoading, setLoading] = useState(false);
  const [layeredDeveloper, setLayeredDeveloper] = useState<string>('');

  const [allData, setAllData] = useState<any[]>([]);
  const [chatData, setChartData] = useState<BarCharRow[]>([]);

  const formatFirstLayer = (data: any[]) => {
    const formatted = data.map((item) => {
      return { value: item.total, legend: item.developer };
    });

    setLayeredDeveloper(null);
    setChartData(formatted);
  };

  const formatByDeveloper = (developer: string) => {
    if (!layeredDeveloper) {
      const developerData = allData.find(
        (item) => item.developer === developer
      );

      const data: BarCharRow[] = [];

      Object.entries(developerData).forEach((item) => {
        if (item[1] > 0 && item[0] !== 'developer' && item[0] !== 'total') {
          data.push({
            legend: item[0].toUpperCase(),
            value: item[1] as number,
            color: get(colors.vulnerabilities, item[0]?.toUpperCase()),
          });
        }
      });

      setLayeredDeveloper(developerData.developer);
      setChartData(data);
    }
  };

  useEffect(() => {
    let isCancelled = false;

    if (filters) {
      setLoading(true);

      analyticService
        .getVulnerabilitiesByDeveloper(filters)
        .then((result: AxiosResponse) => {
          if (!isCancelled) {
            setAllData(result?.data?.content || []);
            formatFirstLayer(result?.data?.content || []);
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
  }, [filters]);

  return (
    <div className="block max-space">
      <BarChart
        isLoading={isLoading}
        data={chatData}
        title={
          layeredDeveloper
            ? `${t(
                'DASHBOARD_SCREEN.VULNERABILITIES_BY_DEV'
              )}: ${layeredDeveloper}`
            : t('DASHBOARD_SCREEN.VULNERABILITIES_BY_DEV')
        }
        onClickRow={(row) => formatByDeveloper(row.legend)}
        onClickBack={() => formatFirstLayer(allData)}
        showBackOption={!!layeredDeveloper}
      />
    </div>
  );
};

export default NewVulnerabilitiesByDeveloper;
