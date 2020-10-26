import keycloak from 'config/keycloak';

const login = () => keycloak.login();

const logout = () => {
  return new Promise((resolve) => {
    resolve();

    keycloak.logout();
  });
};

export default {
  login,
  logout,
};
