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
import i18n from 'config/i18n';
import Details from './Details';
import { FilterVuln } from 'helpers/interfaces/FIlterVuln';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import { useTheme } from 'styled-components';
import { get, find } from 'lodash';
import useWorkspace from 'helpers/hooks/useWorkspace';
import { AxiosError } from 'axios';

const INITIAL_PAGE = 1;

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

  const severitiesOptions = severities.slice(1);

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

        let totalPages = totalItems ? Math.ceil(totalItems / pag.pageSize) : 1;

        if (totalPages <= 0) {
          totalPages = 1;
        }

        setPagination({ ...pag, totalPages, totalItems });
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
        setVulnerabilities([]);
      })
      .finally(() => {
        setLoading(false);
      });
  };

  const isAdminOrSupervisorOfRepository = () => {
    const repository = find(repositories, {
      repositoryID: filters.repositoryID,
    });
    return repository.role === 'admin' || repository.role === 'supervisor';
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
        fetchData(filters, pagination);
        showSuccessFlash(t('VULNERABILITIES_SCREEN.SUCCESS_UPDATE'));
      })
      .catch((err: AxiosError) => {
        dispatchMessage(err?.response?.data);
      });
  };

  useEffect(() => {
    const fetchRepositories = () => {
      repositoryService.getAll(currentWorkspace?.companyID).then((result) => {
        setRepositories(result.data.content);

        if (result.data?.content.length > 0) {
          fetchData(
            { ...filters, repositoryID: result.data?.content[0].repositoryID },
            pagination
          );
        } else {
          setLoading(false);
        }
      });
    };

    fetchRepositories();
    // eslint-disable-next-line
  }, [i18n.language, currentWorkspace]);

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
          optionsHeight="200px"
          hasSearch
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
                  optionsHeight="130px"
                  className="select-role"
                  rounded
                  backgroundColor={get(
                    colors.vulnerabilities,
                    row.severity,
                    colors.vulnerabilities.DEFAULT
                  )}
                  initialValue={row.severity}
                  options={severitiesOptions}
                  disabled={!isAdminOrSupervisorOfRepository()}
                  onChangeValue={(value) =>
                    handleUpdateVulnerabilitySeverity(row, value.value)
                  }
                />
              ),
              status: !isLoading ? (
                <Select
                  keyLabel="description"
                  keyValue="value"
                  width="150px"
                  optionsHeight="130px"
                  className="select-role"
                  rounded
                  initialValue={row.type}
                  options={vulnTypes}
                  disabled={!isAdminOrSupervisorOfRepository()}
                  onChangeValue={(value) =>
                    handleUpdateVulnerabilityType(row, value.value)
                  }
                />
              ) : null,
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
          paginate={{
            pagination,
            onChange: (pag) => fetchData(filters, { ...pag }),
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
