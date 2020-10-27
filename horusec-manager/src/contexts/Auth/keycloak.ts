import { keycloakInstance } from 'config/keycloak';

const login = () => keycloakInstance.login();

const logout = () => {
  return new Promise((resolve) => {
    resolve();

    keycloakInstance.logout();
  });
};

export default {
  login,
  logout,
};
