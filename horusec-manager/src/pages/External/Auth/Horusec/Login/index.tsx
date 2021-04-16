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

import React from 'react';
import Styled from './styled';
import { useHistory, useRouteMatch } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import useAuth from 'helpers/hooks/useAuth';
import { getCurrentConfig } from 'helpers/localStorage/horusecConfig';
import * as Yup from 'yup';

import { Formik } from 'formik';
function LoginScreen() {
  const { t } = useTranslation();
  const history = useHistory();
  const { path } = useRouteMatch();
  const { login, loginInProgress } = useAuth();
  const { disabledBroker } = getCurrentConfig();

  const ValidationScheme = Yup.object({
    email: Yup.string().email(t('LOGIN_SCREEN.INVALID_EMAIL')).required(),
    password: Yup.string().required(t('LOGIN_SCREEN.INVALID_PASS')),
  });

  type InitialValue = Yup.InferType<typeof ValidationScheme>;

  const initialValues: InitialValue = {
    email: '',
    password: '',
  };

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={ValidationScheme}
      onSubmit={(values) => {
        login({ username: values.email, password: values.password }).then(
          () => {
            history.replace('/home');
          }
        );
      }}
    >
      {(props) => (
        <Styled.Form>
          <Styled.Field
            label={t('LOGIN_SCREEN.EMAIL')}
            ariaLabel={t('LOGIN_SCREEN.EMAIL_ARIA')}
            name="email"
          />

          <Styled.Field
            label={t('LOGIN_SCREEN.PASSWORD')}
            ariaLabel={t('LOGIN_SCREEN.PASSWORD_ARIA')}
            name="password"
            type="password"
          />

          {!disabledBroker ? (
            <Styled.ForgotPass
              onClick={() => history.push(`${path}/recovery-password`)}
            >
              {t('LOGIN_SCREEN.FORGOT_PASS')}
            </Styled.ForgotPass>
          ) : null}

          <Styled.Submit
            isDisabled={!props.isValid}
            isLoading={loginInProgress}
            text={t('LOGIN_SCREEN.SUBMIT')}
            type="submit"
            rounded
          />

          <Styled.Register
            onClick={() => history.push(`${path}/create-account`)}
            outline
            text={t('LOGIN_SCREEN.NO_ACCOUNT')}
            rounded
          />
        </Styled.Form>
      )}
    </Formik>
  );
}

export default LoginScreen;
