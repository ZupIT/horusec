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
import ExternalLayout from 'layouts/External';
import useAuth from 'helpers/hooks/useAuth';
import { useTranslation } from 'react-i18next';
import { useHistory } from 'react-router-dom';
import { Formik } from 'formik';
import * as Yup from 'yup';

function LDAPAuth() {
  const { t } = useTranslation();
  const { loginInProgress, login } = useAuth();
  const history = useHistory();

  const ValidationScheme = Yup.object({
    username: Yup.string().required(t('LOGIN_SCREEN.INVALID_USERNAME')),
    password: Yup.string().required(t('LOGIN_SCREEN.INVALID_PASS')),
  });

  type InitialValue = Yup.InferType<typeof ValidationScheme>;

  const initialValues: InitialValue = {
    username: '',
    password: '',
  };

  return (
    <ExternalLayout>
      <Formik
        initialValues={initialValues}
        validationSchema={ValidationScheme}
        onSubmit={(values) => {
          login({ username: values.username, password: values.password }).then(
            () => {
              history.push('/home');
            }
          );
        }}
      >
        {(props) => (
          <Styled.Form>
            <Styled.Field
              label={t('LOGIN_SCREEN.USERNAME')}
              name="username"
              type="text"
            />

            <Styled.Field
              label={t('LOGIN_SCREEN.PASSWORD')}
              name="password"
              type="password"
            />

            <Styled.Submit
              isDisabled={!props.isValid}
              isLoading={loginInProgress}
              text={t('LOGIN_SCREEN.SUBMIT')}
              type="submit"
              rounded
            />
          </Styled.Form>
        )}
      </Formik>
    </ExternalLayout>
  );
}

export default LDAPAuth;
