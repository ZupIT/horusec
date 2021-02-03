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

import React, { Suspense, lazy } from 'react';
import { BrowserRouter, Redirect, Route, Switch } from 'react-router-dom';
import { isMicrofrontend } from 'helpers/localStorage/microfrontend';
import { isLogged } from 'helpers/localStorage/tokens';

const MANAGER_PATH = (window as any).REACT_APP_HORUSEC_MANAGER_PATH || '/';

const Routes = () => (
  <BrowserRouter basename={isMicrofrontend() ? '/horusec' : MANAGER_PATH}>
    <Suspense fallback="">
      <Switch>
        <Route exact path="/">
          {isLogged() ? <Redirect to="/home" /> : <Redirect to="/auth" />}
        </Route>

        <Route
          path="/auth"
          component={lazy(() => import('pages/External/Auth'))}
        />

        <Route path="/home" component={lazy(() => import('pages/Internal'))} />

        <Route component={lazy(() => import('pages/NotFound'))} />
      </Switch>
    </Suspense>
  </BrowserRouter>
);

export default Routes;
