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
import { Redirect, Switch } from 'react-router-dom';

import Dashboard from 'pages/Internal/Dashboard';
import Repositories from 'pages/Internal/Repositories';
import Users from 'pages/Internal/Users';
import Vulnerabilities from 'pages/Internal/Vulnerabilities';
import Webhooks from 'pages/Internal/Webhooks';
import Settings from 'pages/Internal/Settings';
import { PrivateRoute } from 'components';

function InternalRoutes() {
  return (
    <Switch>
      <Redirect
        exact
        from="/dashboard"
        to={
          isAdminOfCompany()
            ? '/dashboard/organization'
            : '/dashboard/repositories'
        }
      />

      <PrivateRoute
        path={'/dashboard/organization'}
        exact
        component={() => <Dashboard type="company" />}
      />

      <PrivateRoute
        path={'/dashboard/repositories'}
        exact
        component={() => <Dashboard type="repository" />}
      />

      <PrivateRoute
        exact
        path={'/vulnerabilities'}
        component={() => <Vulnerabilities />}
      />

      <PrivateRoute
        exact
        path={'/repositories'}
        component={() => <Repositories />}
      />

      <PrivateRoute
        exact
        path={'/organization-users'}
        component={() => <Users />}
      />

      <PrivateRoute exact path={'/webhooks'} component={() => <Webhooks />} />

      <PrivateRoute exact path={'/settings'} component={() => <Settings />} />
    </Switch>
  );
}

export default InternalRoutes;
