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

interface FilterProps {
  onApply: (values: FilterValues) => void;
  type: 'workspace' | 'repository';
}

const Filters: React.FC<FilterProps> = ({ type, onApply }) => {
  const { t } = useTranslation();
  const { showWarningFlash } = useFlashMessage();
  const { currentWorkspace } = useWorkspace();

  const yesterday = new Date();
  yesterday.setDate(yesterday.getDate() - 1);

  const [repositories, setRepositories] = useState<any[]>([]);

  const [filters, setFilters] = useState<FilterValues>({
    initialDate: yesterday,
    finalDate: new Date(),
    repositoryID: null,
    companyID: null,
    type,
  });

  useEffect(() => {
    const fetchRepositories = () => {
      repositoryService.getAll(currentWorkspace?.companyID).then((result) => {
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

    // eslint-disable-next-line
  }, [currentWorkspace]);

  return (
    <Styled.Container>
      <Styled.CalendarWrapper>
        <Calendar
          initialDate={filters.initialDate}
          title={t('DASHBOARD_SCREEN.START_DATE')}
          onChangeValue={(date: Date) =>
            setFilters({ ...filters, initialDate: date })
          }
        />
      </Styled.CalendarWrapper>

      <Styled.CalendarWrapper>
        <Calendar
          title={t('DASHBOARD_SCREEN.FINAL_DATE')}
          onChangeValue={(date: Date) =>
            setFilters({ ...filters, finalDate: date })
          }
        />
      </Styled.CalendarWrapper>

      {type === 'repository' ? (
        <Select
          keyLabel="name"
          width="200px"
          initialValue={repositories[0]}
          options={repositories}
          title={t('DASHBOARD_SCREEN.REPOSITORY')}
          onChangeValue={(value) =>
            setFilters({ ...filters, repositoryID: value.repositoryID })
          }
        />
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
