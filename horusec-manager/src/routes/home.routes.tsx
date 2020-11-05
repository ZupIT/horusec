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

import React, { useEffect } from 'react';
import {
  getCurrentCompany,
  isAdminOfCompany,
} from 'helpers/localStorage/currentCompany';
import {
  useHistory,
  Switch,
  Route,
  useRouteMatch,
  Redirect,
} from 'react-router-dom';

import HomeLayout from 'layouts/Home';

import Dashboard from 'pages/Internal/Home/Dashboard';
import Repositories from 'pages/Internal/Home/Repositories';
import Users from 'pages/Internal/Home/Users';
import Vulnerabilities from 'pages/Internal/Home/Vulnerabilities';
import Webhooks from 'pages/Internal/Home/Webhooks';

function HomeRoutes() {
  const history = useHistory();
  const { path } = useRouteMatch();

  useEffect(() => {
    if (!getCurrentCompany()) {
      history.replace('/organization');
    }
  });

  return (
    <HomeLayout>
      <Switch>
        <Redirect
          exact
          from="/home"
          to={
            isAdminOfCompany()
              ? `${path}/dashboard/organization`
              : `${path}/dashboard/repositories`
          }
        />

        <Route
          path={`${path}/dashboard/organization`}
          component={() => <Dashboard type="company" />}
        />

        <Route
          path={`${path}/dashboard/repositories`}
          component={() => <Dashboard type="repository" />}
        />

        <Route
          exact
          path={`${path}/vulnerabilities`}
          component={() => <Vulnerabilities />}
        />

        <Route
          exact
          path={`${path}/repositories`}
          component={() => <Repositories />}
        />

        <Route
          path={`${path}/organization-users`}
          component={() => <Users />}
        />

        <Route path={`${path}/webhooks`} component={() => <Webhooks />} />
      </Switch>
    </HomeLayout>
  );
}

export default HomeRoutes;
