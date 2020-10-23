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

import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { getCurrentAuthType } from 'helpers/localStorage/currentAuthType';
import { clearCurrentUser } from 'helpers/localStorage/currentUser';
import { clearCurrentCompany } from 'helpers/localStorage/currentCompany';
import { clearTokens } from 'helpers/localStorage/tokens';
import { Authenticator } from 'helpers/interfaces/Authenticator';

import horusec from './horusec';
import keycloak from './keycloak';
import ldap from './ldap';

interface AuthProviderPops {
  children: JSX.Element;
}

interface AuthCtx {
  loginInProgress: boolean;
  login: Function;
  logout: Function;
}

const getAuthenticator = () => {
  const authType = getCurrentAuthType();

  const authenticators: Authenticator = {
    horusec,
    ldap,
    keycloak,
  };

  return authenticators[authType];
};

const AuthContext = React.createContext<AuthCtx>({
  loginInProgress: false,
  login: null,
  logout: null,
});

const AuthProvider = ({ children }: AuthProviderPops) => {
  const [loginInProgress, setLoginInProgress] = useState(false);
  const { dispatchMessage } = useResponseMessage();

  const clearLocalStorage = () => {
    clearCurrentUser();
    clearCurrentCompany();
    clearTokens();
  };

  const login = (email?: string, password?: string): Promise<void> => {
    return new Promise((resolve) => {
      setLoginInProgress(true);

      getAuthenticator()
        .login(email, password)
        .then(() => {
          resolve();
        })
        .catch((err: any) => {
          dispatchMessage(err?.response?.data);
        })
        .finally(() => {
          setLoginInProgress(false);
        });
    });
  };

  const logout = () => {
    return new Promise((resolve) => {
      getAuthenticator()
        .logout()
        .catch((err: any) => {
          dispatchMessage(err?.response?.data);
        })
        .finally(() => {
          clearLocalStorage();
          resolve();
        });
    });
  };

  return (
    <AuthContext.Provider
      value={{
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
