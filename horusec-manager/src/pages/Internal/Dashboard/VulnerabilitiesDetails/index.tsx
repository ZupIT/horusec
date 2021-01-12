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
import { Icon, Pagination } from 'components';
import { FilterValues } from 'helpers/interfaces/FilterValues';
import analyticService from 'services/analytic';
import ReactTooltip from 'react-tooltip';
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

  const fetchData = (currentPage: number, pageSize: number) => {
    setLoading(true);
    if (pageSize !== pagination.pageSize) {
      currentPage = 1;
    }

    analyticService
      .getVulnerabilitiesDetails(filters, currentPage, pageSize)
      .then((result) => {
        formatDataValues(result.data?.content?.data?.analysis);
        const totalItems = result?.data?.content?.data?.totalItems;

        let totalPages = totalItems ? Math.ceil(totalItems / pageSize) : 1;

        if (totalPages <= 0) {
          totalPages = 1;
        }

        setPagination({ currentPage, pageSize, totalPages, totalItems });
      })
      .finally(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    if (filters) {
      fetchData(1, 10);
    }

    // eslint-disable-next-line
  }, [filters]);

  return (
    <div className="max-space">
      <Styled.Wrapper>
        <Styled.Title>
          {t('DASHBOARD_SCREEN.VULNERABILITY_DETAILS')}
        </Styled.Title>

        <Styled.LoadingWrapper isLoading={isLoading}>
          <Icon name="loading" size="200px" className="loading" />
        </Styled.LoadingWrapper>

        <Styled.Table>
          <Styled.Head>
            <Styled.Column>{t('DASHBOARD_SCREEN.LANGUAGE')}</Styled.Column>
            <Styled.Column>{t('DASHBOARD_SCREEN.SEVERITY')}</Styled.Column>
            <Styled.Column>{t('DASHBOARD_SCREEN.AUTHOR')}</Styled.Column>
            <Styled.Column>{t('DASHBOARD_SCREEN.DESCRIPTION')}</Styled.Column>
            <Styled.Column>{t('DASHBOARD_SCREEN.FILE')}</Styled.Column>
            <Styled.Column>{t('DASHBOARD_SCREEN.LINE')}</Styled.Column>
            <Styled.Column>{t('DASHBOARD_SCREEN.CODE')}</Styled.Column>
          </Styled.Head>

          <Styled.Body>
            {!dataValues || dataValues.length <= 0 ? (
              <Styled.EmptyText>
                {t('DASHBOARD_SCREEN.CHART_NO_DATA')}
              </Styled.EmptyText>
            ) : null}

            {dataValues.map((item, index) => (
              <Styled.Row key={index}>
                <Styled.Cell className="small">
                  {item.language || '-'}
                </Styled.Cell>

                <Styled.Cell className="small">
                  {item.severity || '-'}
                </Styled.Cell>

                <Styled.Cell data-for="main" data-tip={item.commitEmail}>
                  {item.commitEmail || '-'}
                </Styled.Cell>

                <Styled.Cell data-for="main" data-tip={item.details}>
                  {item.details || '-'}
                </Styled.Cell>

                <Styled.Cell data-for="main" data-tip={item.file}>
                  {item.file || '-'}
                </Styled.Cell>

                <Styled.Cell className="small">{item.line || '-'}</Styled.Cell>

                <Styled.Cell data-for="main" data-tip={item.code}>
                  {item.code || '-'}
                </Styled.Cell>

                <ReactTooltip id="main" place="top" type="dark" insecure />
              </Styled.Row>
            ))}
          </Styled.Body>

          {dataValues && dataValues.length > 0 ? (
            <Pagination
              pagination={pagination}
              onChange={(pag) => fetchData(pag.currentPage, pag.pageSize)}
            />
          ) : null}
        </Styled.Table>
      </Styled.Wrapper>
    </div>
  );
};

export default VulnerabilitiesDetails;
