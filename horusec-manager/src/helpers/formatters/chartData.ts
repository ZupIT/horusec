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

import { ChartBarStacked } from 'helpers/interfaces/ChartData';
import { formatToHumanDate } from 'helpers/formatters/date';

const formatChartStacked = (
  listOfData: any[],
  labelKey: string,
  labeIsDate?: boolean
) => {
  const formattedData: ChartBarStacked = {
    series: [],
    categories: [],
  };
  const critical: number[] = [];
  const high: number[] = [];
  const medium: number[] = [];
  const low: number[] = [];
  const info: number[] = [];
  const unknown: number[] = [];

  listOfData.forEach((item) => {
    formattedData.categories.push(
      labeIsDate ? formatToHumanDate(item[labelKey]) : item[labelKey]
    );
    critical.push(item?.critical);
    high.push(item?.high);
    medium.push(item?.medium);
    low.push(item?.low);
    info.push(item?.info);
    unknown.push(item?.unknown);
  });

  formattedData.series = [
    { name: 'CRITICAL', data: critical },
    { name: 'HIGH', data: high },
    { name: 'MEDIUM', data: medium },
    { name: 'LOW', data: low },
    { name: 'INFO', data: info },
    { name: 'UNKNOWN', data: unknown },
  ];

  return formattedData;
};

export { formatChartStacked };
