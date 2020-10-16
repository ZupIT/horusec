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

import React, { useEffect, useState } from 'react';
import Styled from './styled';
import { SearchBar, Select, Icon, Pagination } from 'components';
import { useTranslation } from 'react-i18next';
import { getCurrentCompany } from 'helpers/localStorage/currentCompany';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import repositoryService from 'services/repository';
import { Repository } from 'helpers/interfaces/Repository';
import { PaginationInfo } from 'helpers/interfaces/Pagination';
import { Vulnerability } from 'helpers/interfaces/Vulnerability';
import { debounce } from 'lodash';
import i18n from 'config/i18n';
import Details from './Details';
import { FilterVuln } from 'helpers/interfaces/FIlterVuln';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import { useTheme } from 'styled-components';
import { get } from 'lodash';

const INITIAL_PAGE = 1;

const Vulnerabilities: React.FC = () => {
  const { t } = useTranslation();
  const { colors } = useTheme();
  const { dispatchMessage } = useResponseMessage();
  const { showSuccessFlash } = useFlashMessage();
  const { companyID } = getCurrentCompany();
  const [isLoading, setLoading] = useState(true);
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability>(null);
  const [filters, setFilters] = useState<FilterVuln>({
    companyID: companyID,
    repositoryID: null,
    vulnHash: null,
    vulnSeverity: null,
    vulnType: null,
  });
  const [pagination, setPagination] = useState<PaginationInfo>({
    currentPage: INITIAL_PAGE,
    totalItems: 0,
    pageSize: 10,
    totalPages: 10,
  });

  const vulnTypes = [
    {
      value: 'Vulnerability',
      description: t('VULNERABILITIES_SCREEN.STATUS.VULNERABILITY'),
    },
    {
      value: 'Risk Accepted',
      description: t('VULNERABILITIES_SCREEN.STATUS.RISKACCEPTED'),
    },
    {
      value: 'False Positive',
      description: t('VULNERABILITIES_SCREEN.STATUS.FALSEPOSITIVE'),
    },
    {
      value: 'Corrected',
      description: t('VULNERABILITIES_SCREEN.STATUS.CORRECTED'),
    },
  ];

  const severities = [
    {
      value: null,
      description: t('VULNERABILITIES_SCREEN.ALL_SEVERITIES'),
    },
    {
      value: 'HIGH',
      description: 'HIGH',
    },
    {
      value: 'MEDIUM',
      description: 'MEDIUM',
    },
    {
      value: 'LOW',
      description: 'LOW',
    },
    {
      value: 'AUDIT',
      description: 'AUDIT',
    },
    {
      value: 'NOSEC',
      description: 'NOSEC',
    },
    {
      value: 'INFO',
      description: 'INFO',
    },
  ];

  const fetchData = (filt: FilterVuln, pag: PaginationInfo) => {
    setLoading(true);

    if (pag.pageSize !== pagination.pageSize) {
      pag.currentPage = INITIAL_PAGE;
    }

    setFilters(filt);

    filt = {
      ...filt,
      vulnSeverity: filt.vulnHash ? null : filt.vulnSeverity,
      vulnType: filt.vulnHash ? null : filt.vulnType,
    };

    repositoryService
      .getAllVulnerabilities(filt, pag)
      .then((result) => {
        setVulnerabilities(result.data?.content?.data);
        const totalItems = result?.data?.content?.totalItems;

        let totalPages = totalItems ? Math.round(totalItems / pag.pageSize) : 1;

        if (totalPages <= 0) {
          totalPages = 1;
        }

        setPagination({ ...pag, totalPages, totalItems });
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      })
      .finally(() => {
        setLoading(false);
      });
  };

  const handleSearch = debounce((searchString: string) => {
    fetchData({ ...filters, vulnHash: searchString }, pagination);
  }, 500);

  const handleUpdateVulnerabilityType = (
    vulnerability: Vulnerability,
    type: string
  ) => {
    repositoryService
      .updateVulnerabilityType(
        filters.companyID,
        filters.repositoryID,
        vulnerability.vulnerabilityID,
        type
      )
      .then(() => {
        fetchData(filters, pagination);
        showSuccessFlash(t('VULNERABILITIES_SCREEN.SUCCESS_UPDATE'));
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      });
  };

  useEffect(() => {
    const fetchRepositories = () => {
      repositoryService.getAll(companyID).then((result) => {
        setRepositories(result.data.content);

        if (result.data?.content.length > 0) {
          fetchData(
            { ...filters, repositoryID: result.data?.content[0].repositoryID },
            pagination
          );
        }
      });
    };

    fetchRepositories();
    // eslint-disable-next-line
  }, [i18n.language]);

  return (
    <Styled.Wrapper>
      <Styled.Options>
        <SearchBar
          placeholder={t('VULNERABILITIES_SCREEN.SEARCH')}
          onSearch={(value) => handleSearch(value)}
        />

        <Styled.Select
          keyLabel="description"
          width="180px"
          optionsHeight="145px"
          selectText={t('VULNERABILITIES_SCREEN.ALL_SEVERITIES')}
          rounded
          disabled={!!filters.vulnHash}
          options={severities}
          title={t('VULNERABILITIES_SCREEN.SEVERITY')}
          onChangeValue={(item) =>
            fetchData(
              { ...filters, vulnSeverity: item.value },
              { ...pagination, currentPage: INITIAL_PAGE }
            )
          }
        />

        <Styled.Select
          keyLabel="description"
          width="150px"
          selectText={t('VULNERABILITIES_SCREEN.ALL_STATUS')}
          optionsHeight="160px"
          disabled={!!filters.vulnHash}
          rounded
          options={[
            {
              description: t('VULNERABILITIES_SCREEN.ALL_STATUS'),
              value: null,
            },
            ...vulnTypes,
          ]}
          title={t('VULNERABILITIES_SCREEN.STATUS_TITLE')}
          onChangeValue={(item) =>
            fetchData(
              { ...filters, vulnType: item.value },
              { ...pagination, currentPage: INITIAL_PAGE }
            )
          }
        />

        <Select
          keyLabel="name"
          width="220px"
          optionsHeight="100px"
          rounded
          initialValue={repositories[0]}
          options={repositories}
          title={t('VULNERABILITIES_SCREEN.REPOSITORY')}
          onChangeValue={(item) =>
            fetchData(
              { ...filters, repositoryID: item.repositoryID },
              { ...pagination, currentPage: INITIAL_PAGE }
            )
          }
        />
      </Styled.Options>

      <Styled.Content>
        <Styled.LoadingWrapper isLoading={isLoading}>
          <Icon name="loading" size="200px" className="loading" />
        </Styled.LoadingWrapper>

        <Styled.Title>{t('VULNERABILITIES_SCREEN.TITLE')}</Styled.Title>

        <Styled.Table>
          <Styled.Head>
            <Styled.Column>
              {t('VULNERABILITIES_SCREEN.TABLE.HASH')}
            </Styled.Column>
            <Styled.Column>
              {t('VULNERABILITIES_SCREEN.TABLE.DESCRIPTION')}
            </Styled.Column>
            <Styled.Column>
              {t('VULNERABILITIES_SCREEN.TABLE.SEVERITY')}
            </Styled.Column>
            <Styled.Column>
              {t('VULNERABILITIES_SCREEN.TABLE.STATUS')}
            </Styled.Column>
            <Styled.Column>
              {t('VULNERABILITIES_SCREEN.TABLE.DETAILS')}
            </Styled.Column>
          </Styled.Head>

          <Styled.Body>
            {!vulnerabilities || vulnerabilities.length <= 0 ? (
              <Styled.EmptyText>
                {t('VULNERABILITIES_SCREEN.TABLE.EMPTY')}
              </Styled.EmptyText>
            ) : null}

            {vulnerabilities.map((vul, index) => (
              <Styled.Row key={index}>
                <Styled.Cell>{vul.vulnHash}</Styled.Cell>

                <Styled.Cell>{vul.details}</Styled.Cell>

                <Styled.Cell className="center">
                  <Styled.Tag
                    color={get(
                      colors.vulnerabilities,
                      vul.severity,
                      colors.vulnerabilities.DEFAULT
                    )}
                  >
                    {vul.severity}
                  </Styled.Tag>
                </Styled.Cell>

                <Styled.Cell>
                  {!isLoading ? (
                    <Select
                      keyLabel="description"
                      keyValue="value"
                      width="250px"
                      optionsHeight="130px"
                      className="select-type"
                      rounded
                      initialValue={vul.type}
                      options={vulnTypes}
                      onChangeValue={(value) =>
                        handleUpdateVulnerabilityType(vul, value.value)
                      }
                    />
                  ) : null}
                </Styled.Cell>

                <Styled.Cell>
                  <Icon
                    name="info"
                    size="20px"
                    onClick={() => setSelectedVuln(vul)}
                  />
                </Styled.Cell>
              </Styled.Row>
            ))}
          </Styled.Body>

          {vulnerabilities && vulnerabilities.length > 0 ? (
            <Pagination
              pagination={pagination}
              onChange={(pag) => fetchData(filters, { ...pag })}
            />
          ) : null}
        </Styled.Table>
      </Styled.Content>

      <Details
        isOpen={!!selectedVuln}
        onClose={() => setSelectedVuln(null)}
        vulnerability={selectedVuln}
      />
    </Styled.Wrapper>
  );
};

export default Vulnerabilities;
