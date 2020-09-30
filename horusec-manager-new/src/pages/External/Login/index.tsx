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
import { isValidEmail, isEmptyString } from 'helpers/validators';
import { useHistory } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Field } from 'helpers/interfaces/Field';
import useAuth from 'helpers/hooks/useAuth';
import ExternalLayout from 'layouts/External';

function LoginScreen() {
  const { t } = useTranslation();
  const history = useHistory();
  const { login, loginInProgress } = useAuth();

  const [email, setEmail] = useState<Field>({ value: '', isValid: false });
  const [password, setPassword] = useState<Field>({
    value: '',
    isValid: false,
  });

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (email.isValid && password.isValid) {
      login(email.value, password.value).then(() =>
        history.push('/organization')
      );
    }
  };

  return (
    <ExternalLayout>
      <Styled.Form onSubmit={handleSubmit}>
        <Styled.Field
          label={t('EMAIL')}
          name="email"
          type="text"
          onChangeValue={(field: Field) => setEmail(field)}
          invalidMessage={t('INVALID_EMAIL')}
          validation={isValidEmail}
        />

        <Styled.Field
          label={t('PASSWORD')}
          name="password"
          type="password"
          onChangeValue={(field: Field) => setPassword(field)}
          validation={isEmptyString}
          invalidMessage={t('INVALID_PASS')}
        />

        <Styled.ForgotPass onClick={() => history.push('/recovery-password')}>
          {t('FORGOT_PASS')}
        </Styled.ForgotPass>

        <Styled.Submit
          isDisabled={!password.isValid || !email.isValid}
          isLoading={loginInProgress}
          text={t('LOGIN')}
          type="submit"
          rounded
        />

        <Styled.Register
          onClick={() => history.push('/create-account')}
          outline
          text={t('NO_ACCOUNT')}
          rounded
        />
      </Styled.Form>
    </ExternalLayout>
  );
}

export default LoginScreen;
