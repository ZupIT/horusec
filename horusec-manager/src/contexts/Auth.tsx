import React, { useState, useEffect } from 'react';
import accountService from 'services/account';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { User } from 'helpers/interfaces/User';
import {
  getCurrentUser,
  setCurrentUser,
  clearCurrentUser,
} from 'helpers/localStorage/currentUser';
import { clearCurrentCompany } from 'helpers/localStorage/currentCompany';

interface AuthProviderPops {
  children: JSX.Element;
}

interface AuthCtx {
  user: User;
  isLogged: boolean;
  loginInProgress: boolean;
  login: Function;
  logout: Function;
}

const AuthContext = React.createContext<AuthCtx>({
  user: null,
  isLogged: false,
  loginInProgress: false,
  login: null,
  logout: null,
});

const AuthProvider = ({ children }: AuthProviderPops) => {
  const [user, setUser] = useState<User>(null);
  const [loginInProgress, setLoginInProgress] = useState(false);
  const [isLogged, setLogged] = useState(false);

  const { dispatchMessage } = useResponseMessage();

  const login = (email: string, password: string): Promise<void> => {
    return new Promise((resolve) => {
      setLoginInProgress(true);

      accountService
        .login(email, password)
        .then((result) => {
          const userData = result?.data?.content as User;
          setUser(userData);
          setCurrentUser(userData);
          setLogged(true);
          setLoginInProgress(false);
          resolve();
        })
        .catch((err) => {
          dispatchMessage(err?.response?.data);
          setLoginInProgress(false);
        });
    });
  };

  const logout = () => {
    return new Promise((resolve) => {
      accountService
        .logout()
        .then(() => {
          clearCurrentUser();
          clearCurrentCompany();
          resolve();
        })
        .catch((err) => {
          dispatchMessage(err?.response?.data);
        });
    });
  };

  useEffect(() => {
    const user = getCurrentUser();
    setUser(user);
    if (user?.accessToken) setLogged(true);
  }, [isLogged]);

  return (
    <AuthContext.Provider
      value={{
        isLogged,
        user,
        loginInProgress,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export { AuthProvider, AuthContext };
