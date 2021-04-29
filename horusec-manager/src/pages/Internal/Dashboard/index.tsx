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

import React, { useState } from 'react';
import Styled from './styled';
import Filters from './Filters';
import { FilterValues } from 'helpers/interfaces/FilterValues';
import { useTranslation } from 'react-i18next';

import TotalDevelopers from './TotalDevelopers';
import TotalRepositories from './TotalRepositories';
import AllVulnerabilities from './AllVulnerabilities';
import VulnerabilitiesByDeveloper from './VulnerabilitiesByDeveloper';
import VulnerabilitiesByLanguage from './VulnerabilitiesByLanguage';
import VulnerabilitiesByRepository from './VulnerabilitiesByRepository';
import VulnerabilitiesTimeLine from './VulnerabilitiesTimeLine';
import VulnerabilitiesDetails from './VulnerabilitiesDetails';

import NewVulnerabilitiesByDeveloper from './NewVulnerabilitiesByDeveloper';

interface Props {
  type: 'workspace' | 'repository';
}

const Dashboard: React.FC<Props> = ({ type }) => {
  const [filters, setFilters] = useState<FilterValues>(null);
  const { t } = useTranslation();

  return (
    <Styled.Wrapper>
      <Styled.AriaTitle>
        {type === 'workspace'
          ? t('DASHBOARD_SCREEN.ARIA_TITLE_WORKSPACE')
          : t('DASHBOARD_SCREEN.ARIA_TITLE_REPOSITORY')}
      </Styled.AriaTitle>

      <Filters type={type} onApply={(values) => setFilters(values)} />

      <Styled.Row>
        <TotalDevelopers filters={filters} />

        {type === 'workspace' ? <TotalRepositories filters={filters} /> : null}

        <AllVulnerabilities filters={filters} />
      </Styled.Row>

      <Styled.Row>
        <VulnerabilitiesByDeveloper filters={filters} />

        {type === 'workspace' ? (
          <VulnerabilitiesByRepository filters={filters} />
        ) : null}
      </Styled.Row>

      <Styled.Row>
        <NewVulnerabilitiesByDeveloper filters={filters} />

        {type === 'workspace' ? (
          <VulnerabilitiesByRepository filters={filters} />
        ) : null}
      </Styled.Row>

      <Styled.Row>
        <VulnerabilitiesByLanguage filters={filters} />

        <VulnerabilitiesTimeLine filters={filters} />
      </Styled.Row>

      <Styled.Row>
        <VulnerabilitiesDetails filters={filters} />
      </Styled.Row>
    </Styled.Wrapper>
  );
};

export default Dashboard;
