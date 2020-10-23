import keycloak from 'config/keycloak';

const login = () => keycloak.login();

const logout = () => keycloak.logout();

export default {
  login,
  logout,
};
