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
import { Icon } from 'components';
import { FilterValues } from 'helpers/interfaces/FilterValues';
import analyticService from 'services/analytic';
import ReactTooltip from 'react-tooltip';

interface Props {
  filters?: FilterValues;
}

interface DatatableValue {
  language: string;
  severity: string;
  author: string;
  details: string;
  file: string;
  line: string | number;
  code: string;
}

interface Pagination {
  currentPage: number;
  totalItems: number;
  pageSize: number;
  totalPages: number;
}

const VulnerabilitiesDetails: React.FC<Props> = ({ filters }) => {
  const { t } = useTranslation();
  const [isLoading, setLoading] = useState(true);
  const [dataValues, setDataValues] = useState<DatatableValue[]>([]);
  const [pagination, setPagination] = useState<Pagination>({
    currentPage: 1,
    totalItems: 0,
    pageSize: 10,
    totalPages: 0,
  });

  const formatDataValues = (data: any[]) => {
    const formattedData: DatatableValue[] = [];

    data.forEach((item) => {
      const {
        language,
        severity,
        details,
        file,
        line,
        code,
      } = item?.vulnerability;

      formattedData.push({
        language,
        severity,
        author: item?.vulnerability?.commitAuthor.author,
        details,
        file,
        line,
        code,
      });
    });

    setDataValues(formattedData);
  };

  const fetchData = (page: number, size: number, isPageHandle = false) => {
    setLoading(true);
    analyticService
      .getVulnerabilitiesDetails(filters, page, size)
      .then((result) => {
        formatDataValues(result.data?.content?.data?.analysis);

        if (!isPageHandle) {
          const totalItems = result.data?.content?.data?.totalItems;
          const totalPages = totalItems
            ? Math.round(totalItems / pagination.pageSize)
            : 0;

          setPagination({
            ...pagination,
            totalItems,
            totalPages,
          });
        }
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

  const handlePagination = (action: 'next' | 'previous') => {
    let currentPage = pagination.currentPage;
    action === 'next' ? currentPage++ : currentPage--;

    if (currentPage > 0 && currentPage <= pagination.totalPages) {
      setPagination({ ...pagination, currentPage });
      fetchData(currentPage, pagination.pageSize, true);
    }
  };

  return (
    <div className="max-space">
      <Styled.Wrapper>
        <Styled.Title>{t('VULNERABILITY_DETAILS')}</Styled.Title>

        <Styled.LoadingWrapper isLoading={isLoading}>
          <Icon name="loading" size="200px" className="loading" />
        </Styled.LoadingWrapper>

        <Styled.Table>
          <Styled.Head>
            <Styled.Column>{t('LANGUAGE')}</Styled.Column>
            <Styled.Column>{t('SEVERITY')}</Styled.Column>
            <Styled.Column>{t('AUTHOR')}</Styled.Column>
            <Styled.Column>{t('DESCRIPTION')}</Styled.Column>
            <Styled.Column>{t('FILE')}</Styled.Column>
            <Styled.Column>{t('LINE')}</Styled.Column>
            <Styled.Column>{t('CODE')}</Styled.Column>
          </Styled.Head>

          <Styled.Body>
            {!dataValues || dataValues.length <= 0 ? (
              <Styled.EmptyText>{t('CHART_NO_DATA')}</Styled.EmptyText>
            ) : null}

            {dataValues.map((item, index) => (
              <Styled.Row key={index}>
                <Styled.Cell className="small">
                  {item.language || '-'}
                </Styled.Cell>

                <Styled.Cell className="small">
                  {item.severity || '-'}
                </Styled.Cell>

                <Styled.Cell data-for="main" data-tip={item.author}>
                  {item.author || '-'}
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
            <Styled.Pagination>
              <Styled.Button onClick={() => handlePagination('previous')}>
                {t('PREVIOUS_PAGE')}
              </Styled.Button>
              <Styled.CurrentPage>
                {pagination.currentPage} / {pagination.totalPages}
              </Styled.CurrentPage>
              <Styled.Button onClick={() => handlePagination('next')}>
                {t('NEXT_PAGE')}
              </Styled.Button>
            </Styled.Pagination>
          ) : null}
        </Styled.Table>
      </Styled.Wrapper>
    </div>
  );
};

export default VulnerabilitiesDetails;
