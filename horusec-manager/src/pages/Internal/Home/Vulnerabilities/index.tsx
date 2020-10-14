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

const Vulnerabilities: React.FC = () => {
  const { t } = useTranslation();
  const { dispatchMessage } = useResponseMessage();
  const { companyID } = getCurrentCompany();
  const [isLoading, setLoading] = useState(true);
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [currentRepository, setCurrentRepository] = useState<Repository>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [selectedVulnerability, setSelectedVulnerability] = useState<
    Vulnerability
  >(null);
  const [pagination, setPagination] = useState<PaginationInfo>({
    currentPage: 1,
    totalItems: 0,
    pageSize: 10,
    totalPages: 10,
  });

  const vulnTypes = [
    {
      value: 'Vulnerability',
      description: t('VULNERABILITIES_SCREEN.TYPES.VULNERABILITY'),
    },
    {
      value: 'Risk Accepted',
      description: t('VULNERABILITIES_SCREEN.TYPES.RISKACCEPTED'),
    },
    {
      value: 'False Positive',
      description: t('VULNERABILITIES_SCREEN.TYPES.FALSEPOSITIVE'),
    },
    {
      value: 'Corrected',
      description: t('VULNERABILITIES_SCREEN.TYPES.CORRECTED'),
    },
  ];

  const fetchData = (
    currentPage: number,
    pageSize: number,
    repository: Repository,
    vulnHash?: string
  ) => {
    setLoading(true);

    if (repository) {
      setCurrentRepository(repository);
    }

    if (pageSize !== pagination.pageSize) {
      currentPage = 1;
    }

    const repositoryID =
      currentRepository?.repositoryID || repository?.repositoryID;

    repositoryService
      .getAllVulnerabilities(
        companyID,
        repositoryID,
        currentPage,
        pageSize,
        vulnHash
      )
      .then((result) => {
        setVulnerabilities(result.data?.content?.data);
        const totalItems = result?.data?.content?.totalItems;

        let totalPages = totalItems ? Math.round(totalItems / pageSize) : 1;

        if (totalPages <= 0) {
          totalPages = 1;
        }

        setPagination({ currentPage, pageSize, totalPages, totalItems });
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      })
      .finally(() => {
        setLoading(false);
      });
  };

  const handleSearch = debounce((searchString: string) => {
    fetchData(1, pagination.pageSize, null, searchString);
  }, 500);

  const handleUpdateVulnerabilityType = (
    vulnerability: Vulnerability,
    type: string
  ) => {
    repositoryService
      .updateVulnerabilityType(
        companyID,
        currentRepository?.repositoryID,
        vulnerability.vulnerabilityID,
        type
      )
      .then(() => {
        fetchData(pagination.currentPage, pagination.pageSize, null);
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
            pagination.currentPage,
            pagination.pageSize,
            result.data.content[0]
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

        <Select
          keyLabel="name"
          width="250px"
          rounded
          initialValue={repositories[0]}
          options={repositories}
          title={t('VULNERABILITIES_SCREEN.REPOSITORY')}
          onChangeValue={(value) =>
            fetchData(pagination.currentPage, pagination.pageSize, value)
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
              {t('VULNERABILITIES_SCREEN.TABLE.DETAILS')}
            </Styled.Column>
            <Styled.Column>
              {t('VULNERABILITIES_SCREEN.TABLE.SEVERITY')}
            </Styled.Column>
            <Styled.Column>
              {t('VULNERABILITIES_SCREEN.TABLE.TYPE')}
            </Styled.Column>

            <Styled.Column />
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

                <Styled.Cell>{vul.severity}</Styled.Cell>

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
                    name="help"
                    size="20px"
                    onClick={() => setSelectedVulnerability(vul)}
                  />
                </Styled.Cell>
              </Styled.Row>
            ))}
          </Styled.Body>

          {vulnerabilities && vulnerabilities.length > 0 ? (
            <Pagination
              pagination={pagination}
              onChange={(pag) => fetchData(pag.currentPage, pag.pageSize, null)}
            />
          ) : null}
        </Styled.Table>
      </Styled.Content>

      <Details
        isOpen={!!selectedVulnerability}
        onClose={() => setSelectedVulnerability(null)}
        vulnerability={selectedVulnerability}
      />
    </Styled.Wrapper>
  );
};

export default Vulnerabilities;
