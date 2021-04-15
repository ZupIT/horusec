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
import { debounce, get } from 'lodash';
import Details from './Details';
import { FilterVuln } from 'helpers/interfaces/FIlterVuln';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import { useTheme } from 'styled-components';
import { find } from 'lodash';
import useWorkspace from 'helpers/hooks/useWorkspace';
import { AxiosError, AxiosResponse } from 'axios';
import { Autocomplete } from '@material-ui/lab';
import { TextField } from '@material-ui/core';

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
  const [isLoading, setLoading] = useState(false);
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability>(null);
  const [filters, setFilters] = useState<FilterVuln>({
    companyID: currentWorkspace?.companyID,
    repositoryID: repositories[0]?.repositoryID,
    vulnHash: '',
    vulnSeverity: 'All',
    vulnType: 'All',
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
      label: t('VULNERABILITIES_SCREEN.ALL_STATUS'),
      value: 'All',
    },
    {
      label: t('VULNERABILITIES_SCREEN.STATUS.VULNERABILITY'),
      value: 'Vulnerability',
    },
    {
      label: t('VULNERABILITIES_SCREEN.STATUS.RISKACCEPTED'),
      value: 'Risk Accepted',
    },
    {
      label: t('VULNERABILITIES_SCREEN.STATUS.FALSEPOSITIVE'),
      value: 'False Positive',
    },
    {
      label: t('VULNERABILITIES_SCREEN.STATUS.CORRECTED'),
      value: 'Corrected',
    },
  ];

  const severities = [
    {
      label: t('VULNERABILITIES_SCREEN.ALL_SEVERITIES'),
      value: 'All',
    },
    {
      label: 'CRITICAL',
      value: 'CRITICAL',
    },
    {
      label: 'HIGH',
      value: 'HIGH',
    },
    {
      label: 'MEDIUM',
      value: 'MEDIUM',
    },
    {
      label: 'LOW',
      value: 'LOW',
    },
    {
      label: 'INFO',
      value: 'INFO',
    },
    {
      label: 'UNKNOWN',
      value: 'UNKNOWN',
    },
  ];

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
      .then((response: AxiosResponse) => {
        const result: Vulnerability = response.data.content;
        setVulnerabilities((state) =>
          state.map((el) =>
            el.vulnerabilityID === result.vulnerabilityID ? result : el
          )
        );
        showSuccessFlash(t('VULNERABILITIES_SCREEN.SUCCESS_UPDATE'));
      })
      .catch((err: AxiosError) => {
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
      .then((response: AxiosResponse) => {
        showSuccessFlash(t('VULNERABILITIES_SCREEN.SUCCESS_UPDATE'));
        const result: Vulnerability = response.data.content;
        setVulnerabilities((state) =>
          state.map((el) =>
            el.vulnerabilityID === result.vulnerabilityID ? result : el
          )
        );
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
        const filter = refresh.filter;

        if (page.pageSize !== pagination.pageSize) {
          page.currentPage = INITIAL_PAGE;
        }

        if (!filter.repositoryID) {
          filter.repositoryID = repositories[0].repositoryID;
        }

        const filterAux = {
          ...filter,
          vulnSeverity: filter.vulnHash ? null : filter.vulnSeverity,
          vulnType: filter.vulnHash ? null : filter.vulnType,
        };

        setFilters(filter);

        if (filterAux.vulnSeverity === 'All') filterAux.vulnSeverity = null;
        if (filterAux.vulnType === 'All') filterAux.vulnType = null;

        repositoryService
          .getAllVulnerabilities(filterAux, page)
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
  }, [refresh, repositories.length, pagination.pageSize]);

  const getValueRepo = () => {
    const repo = repositories.find(
      (x) => x.repositoryID === filters.repositoryID
    );
    return repo ? { label: repo.name, value: repo.repositoryID } : null;
  };
  console.log(filters.vulnSeverity);
  return (
    <Styled.Wrapper>
      <Styled.Options>
        <SearchBar
          placeholder={t('VULNERABILITIES_SCREEN.SEARCH')}
          onSearch={(value) => handleSearch(value)}
        />

        <Select
          width="250px"
          placeholder={t('VULNERABILITIES_SCREEN.ALL_SEVERITIES')}
          disabled={!!filters.vulnHash}
          options={severities}
          value={filters.vulnSeverity}
          label={t('VULNERABILITIES_SCREEN.SEVERITY')}
          onChangeValue={(item) => {
            setFilters((state) => ({ ...state, vulnSeverity: item }));
            setRefresh({
              filter: { ...filters, vulnSeverity: item },
              page: { ...pagination, currentPage: INITIAL_PAGE },
            });
          }}
        />

        <Styled.Select
          width="250px"
          placeholder={t('VULNERABILITIES_SCREEN.ALL_STATUS')}
          disabled={!!filters.vulnHash}
          options={vulnTypes}
          label={t('VULNERABILITIES_SCREEN.STATUS_TITLE')}
          value={filters.vulnType}
          onChangeValue={(item) => {
            setFilters((state) => ({ ...state, vulnType: item }));
            setRefresh({
              filter: { ...filters, vulnType: item },
              page: { ...pagination, currentPage: INITIAL_PAGE },
            });
          }}
        />

        <Autocomplete
          style={{ width: '250px' }}
          options={repositories.map((el) => ({
            label: el.name,
            value: el.repositoryID,
          }))}
          getOptionLabel={(option) => option.label || ''}
          getOptionSelected={(option, value) => {
            return value !== undefined ? option.value === value.value : false;
          }}
          value={getValueRepo()}
          onChange={(_event, value: any) => {
            setRefresh({
              filter: { ...filters, repositoryID: value.value },
              page: { ...pagination, currentPage: INITIAL_PAGE },
            });
          }}
          renderInput={(params) => (
            <TextField
              {...params}
              label={t('VULNERABILITIES_SCREEN.REPOSITORY')}
              size="small"
              FormHelperTextProps={{ tabIndex: 0 }}
            />
          )}
          disableClearable
          noOptionsText={t('GENERAL.NO_OPTIONS')}
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
                  style={{
                    backgroundColor: get(
                      colors.vulnerabilities,
                      row.severity,
                      colors.vulnerabilities.DEFAULT
                    ),
                  }}
                  width="150px"
                  value={row.severity}
                  options={severities.slice(1)}
                  disabled={!isAdminOrSupervisorOfRepository()}
                  onChangeValue={(value) =>
                    handleUpdateVulnerabilitySeverity(row, value)
                  }
                />
              ),
              status: (
                <Select
                  value={row.type}
                  options={vulnTypes.slice(1)}
                  width="200px"
                  disabled={!isAdminOrSupervisorOfRepository()}
                  onChangeValue={(value) =>
                    handleUpdateVulnerabilityType(row, value)
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
