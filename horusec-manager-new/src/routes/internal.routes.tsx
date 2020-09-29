import React, { lazy } from 'react';
import { Switch } from 'react-router-dom';
import { PrivateRoute } from 'components';

const InternalRoutes = () => (
  <Switch>
    <PrivateRoute
      exact={false}
      path="/organization"
      component={lazy(() => import('./company.routes'))}
    />

    <PrivateRoute
      exact={false}
      path="/home"
      component={lazy(() => import('./home.routes'))}
    />
  </Switch>
);

export default InternalRoutes;
