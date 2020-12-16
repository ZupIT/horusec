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

import React, { useState, FormEvent } from 'react';
import Styled from './styled';
import ExternalLayout from 'layouts/External';
import useAuth from 'helpers/hooks/useAuth';
import { isEmptyString } from 'helpers/validators';
import { useTranslation } from 'react-i18next';
import { Field } from 'helpers/interfaces/Field';
import { useHistory } from 'react-router-dom';

function LDAPAuth() {
  const { t } = useTranslation();
  const { loginInProgress, login } = useAuth();
  const history = useHistory();

  const [username, setUsername] = useState<Field>({
    value: '',
    isValid: false,
  });
  const [password, setPassword] = useState<Field>({
    value: '',
    isValid: false,
  });

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (username.isValid && password.isValid) {
      login({ username: username.value, password: password.value }).then(() => {
        history.push('/dashboard');
      });
    }
  };

  return (
    <ExternalLayout>
      <Styled.Form onSubmit={handleSubmit}>
        <Styled.Field
          label={t('LOGIN_SCREEN.USERNAME')}
          name="username"
          type="text"
          onChangeValue={(field: Field) => setUsername(field)}
          invalidMessage={t('LOGIN_SCREEN.INVALID_USERNAME')}
          validation={isEmptyString}
        />

        <Styled.Field
          label={t('LOGIN_SCREEN.PASSWORD')}
          name="password"
          type="password"
          onChangeValue={(field: Field) => setPassword(field)}
          validation={isEmptyString}
          invalidMessage={t('LOGIN_SCREEN.INVALID_PASS')}
        />

        <Styled.Submit
          isDisabled={!password.isValid || !username.isValid}
          isLoading={loginInProgress}
          text={t('LOGIN_SCREEN.SUBMIT')}
          type="submit"
          rounded
        />
      </Styled.Form>
    </ExternalLayout>
  );
}

export default LDAPAuth;
