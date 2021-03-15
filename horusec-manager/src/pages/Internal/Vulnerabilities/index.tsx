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
import { SearchBar, Select, Icon, Datatable, Datasource } from 'components';
import { useTranslation } from 'react-i18next';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import repositoryService from 'services/repository';
import { Repository } from 'helpers/interfaces/Repository';
import { PaginationInfo } from 'helpers/interfaces/Pagination';
import { Vulnerability } from 'helpers/interfaces/Vulnerability';
import { debounce } from 'lodash';
import Details from './Details';
import { FilterVuln } from 'helpers/interfaces/FIlterVuln';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import { useTheme } from 'styled-components';
import { find } from 'lodash';
import useWorkspace from 'helpers/hooks/useWorkspace';
import { AxiosError, AxiosResponse } from 'axios';

const INITIAL_PAGE = 1;
interface RefreshInterface {
  filter: FilterVuln;
  page: PaginationInfo;
}

const Vulnerabilities: React.FC = () => {
  const { t } = useTranslation();
  const { colors } = useTheme();
  const { dispatchMessage } = useResponseMessage();

  const { showSuccessFlash } = useFlashMessage();
  const { currentWorkspace } = useWorkspace();
  const [isLoading, setLoading] = useState(true);
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability>(null);
  const [filters, setFilters] = useState<FilterVuln>({
    companyID: currentWorkspace?.companyID,
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

  const [refresh, setRefresh] = useState<RefreshInterface>({
    filter: filters,
    page: pagination,
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
      value: 'CRITICAL',
      description: 'CRITICAL',
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
      value: 'INFO',
      description: 'INFO',
    },
    {
      value: 'UNKNOWN',
      description: 'UNKNOWN',
    },
  ];

  const severitiesOptions = severities.slice(1);

  const isAdminOrSupervisorOfRepository = () => {
    const repository = find(repositories, {
      repositoryID: filters.repositoryID,
    });
    return repository.role === 'admin' || repository.role === 'supervisor';
  };

  const handleSearch = debounce((searchString: string) => {
    setRefresh((state) => ({
      ...state,
      filter: { ...state.filter, vulnHash: searchString },
    }));
  }, 800);

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
        showSuccessFlash(t('VULNERABILITIES_SCREEN.SUCCESS_UPDATE'));
      })
      .catch((err) => {
        setRefresh((state) => state);
        dispatchMessage(err?.response?.data);
      });
  };

  const handleUpdateVulnerabilitySeverity = (
    vulnerability: Vulnerability,
    severity: string
  ) => {
    repositoryService
      .updateVulnerabilitySeverity(
        filters.companyID,
        filters.repositoryID,
        vulnerability.vulnerabilityID,
        severity
      )
      .then(() => {
        showSuccessFlash(t('VULNERABILITIES_SCREEN.SUCCESS_UPDATE'));
      })
      .catch((err: AxiosError) => {
        setRefresh((state) => state);
        dispatchMessage(err?.response?.data);
      });
  };

  useEffect(() => {
    let isCancelled = false;

    const fetchRepositories = () => {
      repositoryService
        .getAll(currentWorkspace?.companyID)
        .then((result: AxiosResponse) => {
          if (!isCancelled) {
            const response = result.data.content;
            setRepositories(response);
          }
        });
    };

    fetchRepositories();

    return () => {
      isCancelled = true;
    };
  }, [currentWorkspace]);

  useEffect(() => {
    let isCancelled = false;

    const fetchVulnerabilities = () => {
      if (repositories.length > 0) {
        setLoading(true);

        const page = refresh.page;
        let filter = refresh.filter;

        if (page.pageSize !== pagination.pageSize) {
          page.currentPage = INITIAL_PAGE;
        }

        if (!filter.repositoryID) {
          filter.repositoryID = repositories[0].repositoryID;
        }

        setFilters(filter);

        filter = {
          ...filter,
          vulnSeverity: filter.vulnHash ? null : filter.vulnSeverity,
          vulnType: filter.vulnHash ? null : filter.vulnType,
        };

        repositoryService
          .getAllVulnerabilities(filter, page)
          .then((result: AxiosResponse) => {
            if (!isCancelled) {
              const response = result.data?.content;
              setVulnerabilities(response?.data);
              const totalItems = response?.totalItems;

              let totalPages = totalItems
                ? Math.ceil(totalItems / page.pageSize)
                : 1;

              if (totalPages <= 0) {
                totalPages = 1;
              }

              setPagination({ ...page, totalPages, totalItems });
            }
          })
          .catch((err: AxiosError) => {
            if (!isCancelled) {
              dispatchMessage(err?.response?.data);
              setVulnerabilities([]);
            }
          })
          .finally(() => {
            if (!isCancelled) {
              setLoading(false);
            }
          });
      } else {
        if (!isCancelled) {
          setLoading(false);
        }
      }
    };

    fetchVulnerabilities();
    return () => {
      isCancelled = true;
    };
    // eslint-disable-next-line
  }, [repositories.length, refresh, pagination.pageSize]);

  return (
    <Styled.Wrapper>
      <Styled.Options>
        <SearchBar
          placeholder={t('VULNERABILITIES_SCREEN.SEARCH')}
          onSearch={(value) => handleSearch(value)}
        />

        <Styled.Select
          keyLabel="description"
          width="250px"
          selectText={t('VULNERABILITIES_SCREEN.ALL_SEVERITIES')}
          disabled={!!filters.vulnHash}
          options={severities}
          title={t('VULNERABILITIES_SCREEN.SEVERITY')}
          onChangeValue={(item) =>
            setRefresh({
              filter: { ...filters, vulnSeverity: item.value },
              page: { ...pagination, currentPage: INITIAL_PAGE },
            })
          }
        />

        <Styled.Select
          keyLabel="description"
          width="250px"
          selectText={t('VULNERABILITIES_SCREEN.ALL_STATUS')}
          disabled={!!filters.vulnHash}
          options={[
            {
              description: t('VULNERABILITIES_SCREEN.ALL_STATUS'),
              value: null,
            },
            ...vulnTypes,
          ]}
          title={t('VULNERABILITIES_SCREEN.STATUS_TITLE')}
          onChangeValue={(item) =>
            setRefresh({
              filter: { ...filters, vulnType: item.value },
              page: { ...pagination, currentPage: INITIAL_PAGE },
            })
          }
        />

        <Select
          keyLabel="name"
          width="250px"
          hasSearch
          initialValue={repositories[0]}
          options={repositories}
          title={t('VULNERABILITIES_SCREEN.REPOSITORY')}
          onChangeValue={(item) =>
            setRefresh({
              filter: { ...filters, repositoryID: item.repositoryID },
              page: { ...pagination, currentPage: INITIAL_PAGE },
            })
          }
        />
      </Styled.Options>

      <Styled.Content>
        <Styled.Title>{t('VULNERABILITIES_SCREEN.TITLE')}</Styled.Title>
        <Datatable
          columns={[
            {
              label: t('VULNERABILITIES_SCREEN.TABLE.HASH'),
              property: 'hash',
              type: 'text',
            },
            {
              label: t('VULNERABILITIES_SCREEN.TABLE.DESCRIPTION'),
              property: 'description',
              type: 'text',
            },
            {
              label: t('VULNERABILITIES_SCREEN.TABLE.SEVERITY'),
              property: 'severity',
              type: 'custom',
              cssClass: ['center'],
            },
            {
              label: t('VULNERABILITIES_SCREEN.TABLE.STATUS'),
              property: 'status',
              type: 'custom',
            },
            {
              label: t('VULNERABILITIES_SCREEN.TABLE.DETAILS'),
              property: 'details',
              type: 'custom',
            },
          ]}
          datasource={vulnerabilities.map((row) => {
            const repo: Datasource = {
              ...row,
              id: row.vulnerabilityID,
              hash: row.vulnHash,
              severity: (
                <Select
                  keyLabel="description"
                  keyValue="value"
                  width="150px"
                  className="select-role"
                  backgroundColor={{
                    colors: colors.vulnerabilities,
                    default: colors.vulnerabilities.DEFAULT,
                  }}
                  initialValue={row.severity}
                  options={severitiesOptions}
                  disabled={!isAdminOrSupervisorOfRepository()}
                  onChangeValue={(value) => handleUpdateVulnerabilitySeverity(row, value?.value)
                  }
                />
              ),
              status: (
                <Select
                  keyLabel="description"
                  keyValue="value"
                  width="150px"
                  className="select-role"
                  initialValue={row.type}
                  options={vulnTypes}
                  disabled={!isAdminOrSupervisorOfRepository()}
                  onChangeValue={(value) =>
                    handleUpdateVulnerabilityType(row, value.value)
                  }
                />
              ),
              details: (
                <Icon
                  name="info"
                  size="20px"
                  onClick={() => setSelectedVuln(row)}
                />
              ),
            };
            return repo;
          })}
          isLoading={isLoading}
          emptyListText={t('VULNERABILITIES_SCREEN.TABLE.EMPTY')}
          fixed={false}
          paginate={{
            pagination,
            onChange: (page) => setRefresh({ filter: filters, page }),
          }}
        />
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
