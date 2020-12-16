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
import { isAdminOfCompany } from 'helpers/localStorage/currentCompany';
import { Redirect, Switch, useRouteMatch } from 'react-router-dom';
import { PrivateRoute } from 'components';
import InternalLayout from 'layouts/Internal';

import Dashboard from 'pages/Internal/Dashboard';
import Repositories from 'pages/Internal/Repositories';
import Users from 'pages/Internal/Users';
import Vulnerabilities from 'pages/Internal/Vulnerabilities';
import Webhooks from 'pages/Internal/Webhooks';
import Settings from 'pages/Internal/Settings';
import AddWorkspace from 'pages/Internal/AddWorkspace';

function InternalRoutes() {
  const { path } = useRouteMatch();

  return (
    <InternalLayout>
      <Switch>
        <PrivateRoute
          exact
          path={`${path}/add-workspace`}
          component={() => <AddWorkspace />}
        />

        <PrivateRoute
          exact
          path={`${path}/workspaces`}
          component={() => <h1>Workspaces</h1>}
        />

        <Redirect
          exact
          from={`${path}/dashboard`}
          to={
            isAdminOfCompany()
              ? `${path}/dashboard/organization`
              : `${path}/dashboard/repositories`
          }
        />

        <PrivateRoute
          path={`${path}/dashboard/organization`}
          exact
          component={() => <Dashboard type="company" />}
        />

        <PrivateRoute
          path={`${path}/dashboard/repositories`}
          exact
          component={() => <Dashboard type="repository" />}
        />

        <PrivateRoute
          exact
          path={`${path}/vulnerabilities`}
          component={() => <Vulnerabilities />}
        />

        <PrivateRoute
          exact
          path={`${path}/repositories`}
          component={() => <Repositories />}
        />

        <PrivateRoute
          exact
          path={`${path}/organization-users`}
          component={() => <Users />}
        />

        <PrivateRoute
          exact
          path={`${path}/webhooks`}
          component={() => <Webhooks />}
        />

        <PrivateRoute
          exact
          path={`${path}/settings`}
          component={() => <Settings />}
        />
      </Switch>
    </InternalLayout>
  );
}

export default InternalRoutes;
