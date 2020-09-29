import React, { useState } from 'react';
import Styled from './styled';
import Filters from './Filters';
import { FilterValues } from 'helpers/interfaces/FilterValues';

import TotalDevelopers from './TotalDevelopers';
import TotalRepositories from './TotalRepositories';
import AllVulnerabilities from './AllVulnerabilities';
import VulnerabilitiesByDeveloper from './VulnerabilitiesByDeveloper';
import VulnerabilitiesByLanguage from './VulnerabilitiesByLanguage';
import VulnerabilitiesByRepository from './VulnerabilitiesByRepository';
import VulnerabilitiesTimeLine from './VulnerabilitiesTimeLine';
import VulnerabilitiesDetails from './VulnerabilitiesDetails';

interface Props {
  type: 'company' | 'repository';
}

const Dashboard: React.FC<Props> = ({ type }) => {
  const [filters, setFilters] = useState<FilterValues>(null);

  return (
    <Styled.Wrapper>
      <Filters type={type} onApply={(values) => setFilters(values)} />

      <Styled.Row>
        <TotalDevelopers filters={filters} />

        {type === 'company' ? <TotalRepositories filters={filters} /> : null}

        <AllVulnerabilities filters={filters} />
      </Styled.Row>

      <Styled.Row>
        <VulnerabilitiesByDeveloper filters={filters} />

        {type === 'company' ? (
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
