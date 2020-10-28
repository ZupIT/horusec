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

import React, { useEffect, useState } from 'react';
import { setCurrenConfig } from 'helpers/localStorage/horusecConfig';
import accountService from 'services/account';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { ObjectLiteral } from 'helpers/interfaces/ObjectLiteral';
import { Splash } from 'components';
import { isLogged } from 'helpers/localStorage/tokens';

import HorusecAuth from './Horusec';
import KeycloakAuth from './Keycloak';
import LDAPAuth from './LDAP';
import { useHistory } from 'react-router-dom';

const Auth = () => {
  const { dispatchMessage } = useResponseMessage();
  const history = useHistory();

  const [authType, setAuthType] = useState(null);
  const [isLoading, setLoading] = useState<boolean>(true);

  const getAuthenticator = (auth: string) => {
    const authenticators: ObjectLiteral = {
      horusec: HorusecAuth,
      ldap: LDAPAuth,
      keycloak: KeycloakAuth,
    };

    return authenticators[auth];
  };

  useEffect(() => {
    const fetchConfiguration = () => {
      accountService
        .getHorusecConfig()
        .then((result) => {
          setCurrenConfig(result?.data?.content);
          setAuthType(result?.data?.content?.authType);
        })
        .catch((err) => {
          dispatchMessage(err?.response?.data);
        })
        .finally(() => {
          setLoading(false);
        });
    };

    setTimeout(() => {
      if (isLogged()) {
        history.replace('/home');
      } else {
        fetchConfiguration();
      }
    }, 1000);

    // eslint-disable-next-line
  }, []);

  const renderAuthenticator = () => {
    if (authType) {
      const Authenticator = getAuthenticator(authType);
      return <Authenticator />;
    }
  };

  return (
    <>
      <Splash isVisible={isLoading} />

      {renderAuthenticator()}
    </>
  );
};

export default Auth;
