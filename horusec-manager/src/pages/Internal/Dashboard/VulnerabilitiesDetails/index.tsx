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
import Styled from './styled';
import { useTranslation } from 'react-i18next';
import { Datatable } from 'components';
import { FilterValues } from 'helpers/interfaces/FilterValues';
import analyticService from 'services/analytic';
import { PaginationInfo } from 'helpers/interfaces/Pagination';

interface Props {
  filters?: FilterValues;
}

interface DatatableValue {
  language: string;
  severity: string;
  commitEmail: string;
  details: string;
  file: string;
  line: string | number;
  code: string;
}

const VulnerabilitiesDetails: React.FC<Props> = ({ filters }) => {
  const { t } = useTranslation();
  const [isLoading, setLoading] = useState(true);
  const [dataValues, setDataValues] = useState<DatatableValue[]>([]);

  const [pagination, setPagination] = useState<PaginationInfo>({
    currentPage: 1,
    totalItems: 100,
    pageSize: 10,
    totalPages: 10,
  });

  const [refresh, setRefresh] = useState<PaginationInfo>(pagination);

  const formatDataValues = (data: any[]) => {
    const formattedData: DatatableValue[] = [];

    data.forEach((item) => {
      const {
        language,
        severity,
        commitEmail,
        details,
        file,
        line,
        code,
      } = item?.vulnerability;

      formattedData.push({
        language,
        severity,
        commitEmail,
        details,
        file,
        line,
        code,
      });
    });

    setDataValues(formattedData);
  };

  useEffect(() => {
    let isCancelled = false;

    if (filters) {
      setLoading(true);
      const page = refresh;

      if (page.pageSize !== pagination.pageSize) {
        page.currentPage = 1;
      }

      analyticService
        .getVulnerabilitiesDetails(filters, page.currentPage, page.pageSize)
        .then((result) => {
          if (!isCancelled) {
            formatDataValues(result.data?.content?.data?.analysis);
            const totalItems = result?.data?.content?.data?.totalItems;

            let totalPages = totalItems
              ? Math.ceil(totalItems / page.pageSize)
              : 1;

            if (totalPages <= 0) {
              totalPages = 1;
            }

            setPagination({ ...page, totalPages, totalItems });
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
  }, [filters, refresh, pagination.pageSize]);

  return (
    <div className="max-space">
      <Styled.Wrapper>
        <Styled.Title>
          {t('DASHBOARD_SCREEN.VULNERABILITY_DETAILS')}
        </Styled.Title>

        <Datatable
          columns={[
            {
              label: t('DASHBOARD_SCREEN.LANGUAGE'),
              property: 'language',
              type: 'text',
            },
            {
              label: t('DASHBOARD_SCREEN.SEVERITY'),
              property: 'severity',
              type: 'text',
            },
            {
              label: t('DASHBOARD_SCREEN.AUTHOR'),
              property: 'commitEmail',
              type: 'text',
            },
            {
              label: t('DASHBOARD_SCREEN.DESCRIPTION'),
              property: 'details',
              type: 'text',
            },
            {
              label: t('DASHBOARD_SCREEN.FILE'),
              property: 'file',
              type: 'text',
            },
            {
              label: t('DASHBOARD_SCREEN.LINE'),
              property: 'line',
              type: 'text',
            },
            {
              label: t('DASHBOARD_SCREEN.CODE'),
              property: 'code',
              type: 'text',
            },
          ]}
          datasource={dataValues}
          paginate={{
            pagination,
            onChange: (pag) => setRefresh(pag),
          }}
          isLoading={isLoading}
          emptyListText={t('DASHBOARD_SCREEN.CHART_NO_DATA')}
          tooltip={{ id: 'main', place: 'top', type: 'dark', insecure: true }}
        />
      </Styled.Wrapper>
    </div>
  );
};

export default VulnerabilitiesDetails;
