import React from 'react';
import { Route, Redirect } from 'react-router-dom';
import { getCurrentUser } from 'helpers/localStorage/currentUser';

interface PrivateRouteProps {
  component: React.FC;
  path: string;
  exact: boolean;
}

const PrivateRoute: React.FC<PrivateRouteProps> = (props) => {
  const user = getCurrentUser();
  const hasAccessToken = user?.accessToken;

  return hasAccessToken ? (
    <Route path={props.path} exact={props.exact} component={props.component} />
  ) : (
    <Redirect to="/login" />
  );
};

export default PrivateRoute;
