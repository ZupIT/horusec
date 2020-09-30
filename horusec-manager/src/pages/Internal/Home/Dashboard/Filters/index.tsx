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
import { getCurrentCompany } from 'helpers/localStorage/currentCompany';
import repositoryService from 'services/repository';

interface FilterProps {
  onApply: (values: FilterValues) => void;
  type: 'company' | 'repository';
}

const Filters: React.FC<FilterProps> = ({ type, onApply }) => {
  const { t } = useTranslation();
  const { companyID } = getCurrentCompany();

  const yesterday = new Date();
  yesterday.setDate(yesterday.getDate() - 1);

  const [repositories, setRepositories] = useState<any[]>([]);
  const [filters, setFilters] = useState<FilterValues>({
    initialDate: yesterday,
    finalDate: new Date(),
    repositoryID: null,
    companyID,
  });

  useEffect(() => {
    const fetchRepositories = () => {
      repositoryService.getAll(companyID).then((result) => {
        setRepositories(result.data.content);
        setFilters({
          ...filters,
          repositoryID: result?.data?.content[0]?.repositoryID,
        });
        onApply({
          ...filters,
          repositoryID: result?.data?.content[0]?.repositoryID,
        });
      });
    };

    if (type === 'repository') {
      fetchRepositories();
    } else if (filters) {
      onApply(filters);
    }
    // eslint-disable-next-line
  }, []);

  return (
    <Styled.Container>
      <Styled.CalendarWrapper>
        <Calendar
          initialDate={filters.initialDate}
          title={t('START_DATE')}
          onChangeValue={(date: Date) =>
            setFilters({ ...filters, initialDate: date })
          }
        />
      </Styled.CalendarWrapper>

      <Styled.CalendarWrapper>
        <Calendar
          title={t('FINAL_DATE')}
          onChangeValue={(date: Date) =>
            setFilters({ ...filters, finalDate: date })
          }
        />
      </Styled.CalendarWrapper>

      {type === 'repository' ? (
        <Select
          keyLabel="name"
          width="200px"
          options={repositories}
          title={t('REPOSITORY')}
          onChangeValue={(value) =>
            setFilters({ ...filters, repositoryID: value.repositoryID })
          }
        />
      ) : null}

      <Styled.ApplyButton
        text={t('APPLY')}
        rounded
        width={78}
        onClick={() => onApply(filters)}
      />
    </Styled.Container>
  );
};

export default Filters;
