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
import moment from 'moment';

const formatChartStacked = (
  listOfData: any[],
  labelKey: string,
  labeIsDate?: boolean
) => {
  const formattedData: ChartBarStacked = {
    series: [],
    categories: [],
  };
  const high: number[] = [];
  const low: number[] = [];
  const medium: number[] = [];
  const noSec: number[] = [];
  const audit: number[] = [];

  listOfData.forEach((item) => {
    formattedData.categories.push(
      labeIsDate ? moment(item[labelKey]).format('DD/MM/yyyy') : item[labelKey]
    );
    high.push(item?.high);
    medium.push(item?.medium);
    noSec.push(item?.noSec);
    low.push(item?.low);
    audit.push(item?.audit);
  });

  formattedData.series = [
    { name: 'HIGH', data: high },
    { name: 'MEDIUM', data: medium },
    { name: 'LOW', data: low },
    { name: 'AUDIT', data: audit },
    { name: 'NOSEC', data: noSec },
  ];

  return formattedData;
};

export { formatChartStacked };
