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
