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
import { setCurrenAuthType } from 'helpers/localStorage/currentAuthType';
import accountService from 'services/account';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { ObjectLiteral } from 'helpers/interfaces/ObjectLiteral';
import { useKeycloak } from '@react-keycloak/web';
import { Splash } from 'components';

import HorusecAuth from './Horusec';
import KeycloakAuth from './Keycloak';
import LDAPAuth from './LDAP';

const Auth = () => {
  const { dispatchMessage } = useResponseMessage();
  const { keycloak } = useKeycloak();

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
    const getAuthType = () => {
      setLoading(true);

      accountService
        .getAuthType()
        .then((result) => {
          setCurrenAuthType(result?.data?.content);
          setAuthType(result?.data?.content);
        })
        .catch((err) => {
          dispatchMessage(err?.response?.data);
          console.log(err);
        })
        .finally(() => {
          setLoading(false);
        });
    };

    getAuthType();
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
