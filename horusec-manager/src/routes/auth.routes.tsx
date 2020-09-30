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
import { Route, Switch } from 'react-router-dom';

const AuthRoutes = () => (
  <Switch>
    <Route
      exact
      path="/login"
      component={lazy(() => import('pages/External/Login'))}
    />

    <Route
      exact
      path="/create-account"
      component={lazy(() => import('pages/External/CreateAccount'))}
    />

    <Route
      exact
      path="/recovery-password"
      component={lazy(() =>
        import('pages/External/RecoveryPassword/SendEmail')
      )}
    />

    <Route
      exact
      path="/recovery-password/check-code"
      component={lazy(() =>
        import('pages/External/RecoveryPassword/CheckCode')
      )}
    />

    <Route
      exact
      path="/recovery-password/new-password"
      component={lazy(() =>
        import('pages/External/RecoveryPassword/NewPassword')
      )}
    />
  </Switch>
);

export default AuthRoutes;
