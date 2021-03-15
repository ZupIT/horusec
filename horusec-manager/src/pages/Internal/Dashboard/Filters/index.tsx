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
import { Calendar, Select } from 'components';
import { FilterValues } from 'helpers/interfaces/FilterValues';
import repositoryService from 'services/repository';
import useWorkspace from 'helpers/hooks/useWorkspace';
import { Repository } from 'helpers/interfaces/Repository';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import { ObjectLiteral } from 'helpers/interfaces/ObjectLiteral';
import { AxiosResponse } from 'axios';
interface FilterProps {
  onApply: (values: FilterValues) => void;
  type: 'workspace' | 'repository';
}

const Filters: React.FC<FilterProps> = ({ type, onApply }) => {
  const { t } = useTranslation();
  const { showWarningFlash } = useFlashMessage();
  const { currentWorkspace } = useWorkspace();

  const fixedRanges = [
    {
      label: t('DASHBOARD_SCREEN.BEGINNING'),
      value: 'beginning',
    },
    {
      label: t('DASHBOARD_SCREEN.CUSTOM_RANGE'),
      value: 'customRange',
    },
    {
      label: t('DASHBOARD_SCREEN.TODAY'),
      value: 'today',
    },
    {
      label: t('DASHBOARD_SCREEN.LAST_WEEK'),
      value: 'lastWeek',
    },
    {
      label: t('DASHBOARD_SCREEN.LAST_MONTH'),
      value: 'lastMonth',
    },
  ];

  const today = new Date();
  const lastWeek = new Date(new Date().setDate(today.getDate() - 7));
  const lastMonth = new Date(new Date().setDate(today.getDate() - 30));

  const [repositories, setRepositories] = useState<any[]>([]);
  const [selectedPeriod, setSelectedPeriod] = useState(fixedRanges[0]);

  const [filters, setFilters] = useState<FilterValues>({
    initialDate: null,
    finalDate: null,
    repositoryID: null,
    companyID: null,
    type,
  });

  const handleSelectedPeriod = (item: { label: string; value: string }) => {
    setSelectedPeriod(item);

    const getRangeOfPeriod: ObjectLiteral = {
      customRange: [today, today],
      today: [today, today],
      lastWeek: [lastWeek, today],
      lastMonth: [lastMonth, today],
      beginning: [null, null],
    };
    setFilters({
      ...filters,
      initialDate: getRangeOfPeriod[item.value][0],
      finalDate: getRangeOfPeriod[item.value][1],
    });
  };

  useEffect(() => {
    let isCancelled = false;
    const fetchRepositories = () => {
      repositoryService
        .getAll(currentWorkspace?.companyID)
        .then((result: AxiosResponse) => {
          if (!isCancelled) {
            const repositories: Repository[] = result.data.content;
            setRepositories(repositories);

            if (repositories.length > 0) {
              setFilters({
                ...filters,
                repositoryID: repositories[0]?.repositoryID,
              });
              onApply({
                ...filters,
                repositoryID: repositories[0]?.repositoryID,
              });
            } else {
              showWarningFlash(t('API_ERRORS.EMPTY_REPOSITORY'), 5200);
            }
          }
        });
    };

    if (currentWorkspace) {
      if (type === 'repository') {
        fetchRepositories();
      } else if (filters) {
        onApply({
          ...filters,
          companyID: currentWorkspace.companyID,
        });
      }
    }
    return function () {
      isCancelled = true;
    };
    // eslint-disable-next-line
  }, [currentWorkspace]);

  return (
    <Styled.Container>
      <Styled.Wrapper>
        <Select
          keyLabel="label"
          appearance="underline"
          width="200px"
          initialValue={selectedPeriod}
          options={fixedRanges}
          title={t('DASHBOARD_SCREEN.PERIOD')}
          onChangeValue={(item) => handleSelectedPeriod(item)}
        />
      </Styled.Wrapper>

      {selectedPeriod?.value === fixedRanges[1].value ? (
        <>
          <Styled.CalendarWrapper>
            <Calendar
              initialDate={filters.initialDate}
              title={t('DASHBOARD_SCREEN.START_DATE')}
              onChangeValue={(field) =>
                setFilters({ ...filters, initialDate: field.value })
              }
            />
          </Styled.CalendarWrapper>

          <Styled.CalendarWrapper>
            <Calendar
              title={t('DASHBOARD_SCREEN.FINAL_DATE')}
              onChangeValue={(field) =>
                setFilters({ ...filters, finalDate: field.value })
              }
            />
          </Styled.CalendarWrapper>
        </>
      ) : null}

      {type === 'repository' ? (
         <Styled.Wrapper>
        <Select
          keyLabel="name"
          appearance="underline"
          initialValue={repositories[0]}
          options={repositories}
          title={t('DASHBOARD_SCREEN.REPOSITORY')}
          hasSearch
          onChangeValue={(value) =>
            setFilters({ ...filters, repositoryID: value.repositoryID })
          }
        />
        </Styled.Wrapper>
      ) : null}

      <Styled.ApplyButton
        text={t('DASHBOARD_SCREEN.APPLY')}
        rounded
        width={78}
        onClick={() =>
          onApply({ ...filters, companyID: currentWorkspace.companyID })
        }
      />
    </Styled.Container>
  );
};

export default Filters;
