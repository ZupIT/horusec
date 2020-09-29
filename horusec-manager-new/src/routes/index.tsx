import React, { Suspense } from 'react';
import { BrowserRouter, Redirect } from 'react-router-dom';
import AuthRoutes from './auth.routes';
import InternalRoutes from './internal.routes';
import { getCurrentUser } from 'helpers/localStorage/currentUser';
import moment from 'moment';

const tokenExpired = (): boolean => {
  const user = getCurrentUser();

  if (!user || !user?.expiresAt) return true;

  const now = moment();
  const expires = moment(user?.expiresAt);

  return expires.isSameOrBefore(now);
};

const Routes = () => (
  <BrowserRouter>
    <Suspense fallback="">
      <AuthRoutes />

      <InternalRoutes />

      <Redirect exact from="/" to={tokenExpired() ? '/login' : '/home'} />
    </Suspense>
  </BrowserRouter>
);

export default Routes;
