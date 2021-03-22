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
import { Counter } from 'components';
import { useTranslation } from 'react-i18next';
import { FilterValues } from 'helpers/interfaces/FilterValues';
import analyticService from 'services/analytic';
import { AxiosResponse } from 'axios';

interface Props {
  filters?: FilterValues;
}

const TotalDevelopers: React.FC<Props> = ({ filters }) => {
  const { t } = useTranslation();

  const [total, setTotal] = useState(null);
  const [isLoading, setLoading] = useState(false);

  useEffect(() => {
    let isCancelled = false;
    if (filters) {
      setLoading(true);

      analyticService
        .getTotalDevelopers(filters)
        .then((result: AxiosResponse) => {
          if (!isCancelled) {
            setTotal(result.data.content);
          }
        })
        .catch(() => {
          if (!isCancelled) {
            setTotal(null);
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
    <div className="block half-space">
      <Counter
        value={total}
        isLoading={isLoading}
        title={t('DASHBOARD_SCREEN.TOTAL_DEVELOPERS')}
      />
    </div>
  );
};

export default TotalDevelopers;
