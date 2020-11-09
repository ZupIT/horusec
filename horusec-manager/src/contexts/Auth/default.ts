import accountService from 'services/account';
import { setTokens } from 'helpers/localStorage/tokens';
import { setCurrentUser } from 'helpers/localStorage/currentUser';
import { LoginParams } from 'helpers/interfaces/LoginParams';

const login = (params: LoginParams) => {
  return new Promise((resolve, reject) => {
    accountService
      .login(params)
      .then((result) => {
        const userData = result?.data?.content;
        const { accessToken, refreshToken, expiresAt } = userData;

        setCurrentUser(userData);
        setTokens(accessToken, refreshToken, expiresAt);
        resolve();
      })
      .catch((err) => reject(err));
  });
};

const logout = () => accountService.logout();

export default {
  login,
  logout,
};
