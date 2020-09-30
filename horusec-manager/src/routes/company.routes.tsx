import React from 'react';

import { CompanyProvider } from 'contexts/Company';
import { Route, useRouteMatch, Switch } from 'react-router-dom';
import CompanyLayout from 'layouts/Company';

import ListCompanies from 'pages/Internal/Company/List';
import AddCompany from 'pages/Internal/Company/Add';
import EditCompany from 'pages/Internal/Company/Edit';

function CompanyRoutes() {
  const { path } = useRouteMatch();

  return (
    <CompanyProvider>
      <CompanyLayout>
        <Switch>
          <Route exact path={path} component={ListCompanies} />

          <Route exact path={`${path}/add`} component={AddCompany} />

          <Route path={`${path}/edit/:companyId`} component={EditCompany} />
        </Switch>
      </CompanyLayout>
    </CompanyProvider>
  );
}

export default CompanyRoutes;
