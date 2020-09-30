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
