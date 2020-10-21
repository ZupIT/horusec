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

import React, { lazy } from 'react';
import ExternalLayout from 'layouts/External';
import { Route, useRouteMatch, Switch } from 'react-router-dom';

function HorusecAuth() {
  const { path } = useRouteMatch();

  return (
    <ExternalLayout>
      <Switch>
        <Route exact path={path} component={lazy(() => import('./Login'))} />

        <Route
          exact
          path="/create-account"
          component={lazy(() => import('./CreateAccount'))}
        />

        <Route
          exact
          path="/recovery-password"
          component={lazy(() => import('./RecoveryPassword/SendEmail'))}
        />

        <Route
          exact
          path="/recovery-password/check-code"
          component={lazy(() => import('./RecoveryPassword/CheckCode'))}
        />

        <Route
          exact
          path="/recovery-password/new-password"
          component={lazy(() => import('./RecoveryPassword/NewPassword'))}
        />
      </Switch>
    </ExternalLayout>
  );
}

export default HorusecAuth;
