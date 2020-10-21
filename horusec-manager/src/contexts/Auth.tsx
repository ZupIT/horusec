/**
 * Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import React, { useState } from 'react';
import accountService from 'services/account';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { User } from 'helpers/interfaces/User';
import {
  setCurrentUser,
  clearCurrentUser,
} from 'helpers/localStorage/currentUser';
import { clearCurrentCompany } from 'helpers/localStorage/currentCompany';

interface AuthProviderPops {
  children: JSX.Element;
}

interface AuthCtx {
  user: User;
  loginInProgress: boolean;
  login: Function;
  logout: Function;
}

const AuthContext = React.createContext<AuthCtx>({
  user: null,
  loginInProgress: false,
  login: null,
  logout: null,
});

const AuthProvider = ({ children }: AuthProviderPops) => {
  const [user, setUser] = useState<User>(null);
  const [loginInProgress, setLoginInProgress] = useState(false);

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

  return (
    <AuthContext.Provider
      value={{
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
