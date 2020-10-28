import accountService from 'services/account';
import { setTokens } from 'helpers/localStorage/tokens';
import { setCurrentUser } from 'helpers/localStorage/currentUser';

const login = (email: string, password: string) => {
  return new Promise((resolve, reject) => {
    accountService
      .login(email, password)
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
