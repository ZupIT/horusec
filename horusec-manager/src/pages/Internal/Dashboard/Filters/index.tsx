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
import { Form, Formik } from 'formik';
import * as Yup from 'yup';
import SearchSelect from 'components/SearchSelect';
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

  const [repositories, setRepositories] = useState<Repository[]>([]);

  const ValidationScheme = Yup.object({
    period: Yup.string().notRequired(),
    initialDate: Yup.date().notRequired(),
    finalDate: Yup.date().notRequired(),
    repositoryID: Yup.string().required(),
    companyID: Yup.string().required(),
    type: Yup.string().oneOf(['workspace', 'repository']).required(),
  });

  const initialValues: FilterValues = {
    period: fixedRanges[0].value,
    initialDate: null,
    finalDate: null,
    repositoryID: repositories[0]?.repositoryID,
    companyID: repositories[0]?.companyID,
    type: type,
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
              onApply({
                ...initialValues,
                repositoryID: repositories[0]?.repositoryID,
                companyID: repositories[0]?.companyID,
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
      } else {
        onApply({
          ...initialValues,
          companyID: currentWorkspace.companyID,
        });
      }
    }
    return function () {
      isCancelled = true;
    };
    // eslint-disable-next-line
  }, [currentWorkspace]);

  const getRangeOfPeriod: ObjectLiteral = {
    beginning: [null, null],
    customRange: [today, today],
    today: [today, today],
    lastWeek: [lastWeek, today],
    lastMonth: [lastMonth, today],
  };

  return (
    <Formik
      initialValues={initialValues}
      enableReinitialize={true}
      validationSchema={ValidationScheme}
      onSubmit={(values) => {
        if (values.period !== fixedRanges[1].value) {
          values.initialDate = getRangeOfPeriod[values.period][0];
          values.finalDate = getRangeOfPeriod[values.period][1];
        } else {
          values.initialDate = new Date(values.initialDate);
          values.finalDate = new Date(values.finalDate);
        }

        onApply(values);
      }}
    >
      {(props) => (
        <Styled.Container>
          <Styled.Wrapper>
            <SearchSelect
              name="period"
              label={t('DASHBOARD_SCREEN.PERIOD')}
              options={fixedRanges}
            />
          </Styled.Wrapper>
          {props.values.period === fixedRanges[1].value ? (
            <>
              <Styled.CalendarWrapper>
                <Calendar
                  name="initialDate"
                  label={t('DASHBOARD_SCREEN.START_DATE')}
                />
              </Styled.CalendarWrapper>

              <Styled.CalendarWrapper>
                <Calendar
                  name="finalDate"
                  label={t('DASHBOARD_SCREEN.FINAL_DATE')}
                />
              </Styled.CalendarWrapper>
            </>
          ) : null}
          {type === 'repository' ? (
            <Styled.Wrapper>
              <SearchSelect
                name="repositoryID"
                label={t('DASHBOARD_SCREEN.REPOSITORY')}
                options={repositories.map((el) => ({
                  label: el.name,
                  value: el.repositoryID,
                }))}
              />
            </Styled.Wrapper>
          ) : null}
          <Styled.ApplyButton
            text={t('DASHBOARD_SCREEN.APPLY')}
            rounded
            width={78}
            type="submit"
          />
        </Styled.Container>
      )}
    </Formik>
  );
};

export default Filters;
