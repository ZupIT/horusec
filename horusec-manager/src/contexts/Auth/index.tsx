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

import React, { useState, useEffect } from 'react';

import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { getCurrentConfig } from 'helpers/localStorage/horusecConfig';
import { clearCurrentUser } from 'helpers/localStorage/currentUser';
import { clearTokens } from 'helpers/localStorage/tokens';
import { Authenticator } from 'helpers/interfaces/Authenticator';
import accountService from 'services/account';
import { setCurrenConfig } from 'helpers/localStorage/horusecConfig';

import defaultAuth from './default';
import keycloakAuth from './keycloak';
import { LoginParams } from 'helpers/interfaces/LoginParams';

const MANAGER_PATH: string =
  (window as any).REACT_APP_HORUSEC_MANAGER_PATH || '';

interface AuthProviderPops {
  children: JSX.Element;
}

interface AuthCtx {
  loginInProgress: boolean;
  fetchConfigInProgress: boolean;
  login(params?: LoginParams): Promise<void>;
  logout(): Promise<void>;
}

const getAuthenticator = () => {
  const { authType } = getCurrentConfig();

  const authenticators: Authenticator = {
    horusec: defaultAuth,
    ldap: defaultAuth,
    keycloak: keycloakAuth,
  };

  return authenticators[authType];
};

const AuthContext = React.createContext<AuthCtx>({
  loginInProgress: false,
  fetchConfigInProgress: false,
  login: null,
  logout: null,
});

const AuthProvider = ({ children }: AuthProviderPops) => {
  const [loginInProgress, setLoginInProgress] = useState(false);
  const [fetchConfigInProgress, setFetchConfigInProgress] = useState(false);
  const { dispatchMessage } = useResponseMessage();

  const clearLocalStorage = () => {
    clearCurrentUser();
    clearTokens();
  };

  const login = (params?: LoginParams): Promise<void> => {
    return new Promise((resolve) => {
      setLoginInProgress(true);

      getAuthenticator()
        .login(params)
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

  const logout = (): Promise<void> => {
    const authenticator = getAuthenticator();

    if (authenticator) {
      return new Promise((resolve) => {
        getAuthenticator()
          .logout()
          .finally(() => {
            resolve();
            clearLocalStorage();
            window.location.replace(
              `${
                MANAGER_PATH.endsWith('/')
                  ? MANAGER_PATH.slice(0, -1)
                  : MANAGER_PATH
              }/auth`
            );
          });
      });
    } else {
      clearLocalStorage();
      window.location.replace('/auth');
    }
  };

  useEffect(() => {
    setFetchConfigInProgress(true);

    accountService
      .getHorusecConfig()
      .then((result) => {
        setCurrenConfig(result?.data?.content);
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      })
      .finally(() => {
        setFetchConfigInProgress(false);
      });
    // eslint-disable-next-line
  }, []);

  return (
    <AuthContext.Provider
      value={{
        loginInProgress,
        fetchConfigInProgress,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export { AuthProvider, AuthContext };
