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
                {t('DASHBOARD_SCREEN.PREVIOUS_PAGE')}
              </Styled.Button>
              <Styled.CurrentPage>
                {pagination.currentPage} / {pagination.totalPages}
              </Styled.CurrentPage>
              <Styled.Button onClick={() => handlePagination('next')}>
                {t('DASHBOARD_SCREEN.NEXT_PAGE')}
              </Styled.Button>
            </Styled.Pagination>
          ) : null}
        </Styled.Table>
      </Styled.Wrapper>
    </div>
  );
};

export default VulnerabilitiesDetails;
