import React, { useEffect } from 'react';
import { getCurrentCompany } from 'helpers/localStorage/currentCompany';
import {
  useHistory,
  Switch,
  Route,
  useRouteMatch,
  Redirect,
} from 'react-router-dom';

import HomeLayout from '../layouts/Home';

import Dashboard from '../pages/Internal/Home/Dashboard';
import Repositories from '../pages/Internal/Home/Repositories';
import Users from '../pages/Internal/Home/Users';

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
        <Redirect exact from="/home" to={`${path}/dashboard/organization`} />

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
          path={`${path}/repositories`}
          component={() => <Repositories />}
        />

        <Route
          path={`${path}/organization-users`}
          component={() => <Users />}
        />
      </Switch>
    </HomeLayout>
  );
}

export default HomeRoutes;
