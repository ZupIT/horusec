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
import Styled from './styled';
import { useHistory } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import accountService from 'services/account';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import queryString from 'query-string';
import * as Yup from 'yup';
import { Formik } from 'formik';

function CheckCode() {
  const { t } = useTranslation();
  const history = useHistory();
  const { dispatchMessage } = useResponseMessage();

  const [code, setCode] = useState('');
  const [email, setEmail] = useState('');

  useEffect(() => {
    const params = queryString.parse(window.location.search);

    if (params?.email) {
      const value = params?.email as string;
      setEmail(value);
    }

    if (params?.code) {
      const value = params?.code as string;
      setCode(value);
    }
  }, []);

  const handleSubmit = (email: string, code: string) => {
    if (code) {
      accountService
        .validateCode(email, code)
        .then((result) => {
          const token = result?.data?.content;
          history.push(`/auth/recovery-password/new-password?token=${token}`);
        })
        .catch((err) => {
          dispatchMessage(err?.response?.data);
        });
    }
  };

  const ValidationScheme = Yup.object({
    email: Yup.string()
      .email(t('RECOVERY_PASS_SCREEN.INVALID_EMAIL'))
      .required(t('RECOVERY_PASS_SCREEN.INVALID_EMAIL')),
    code: Yup.string().required(t('RECOVERY_PASS_SCREEN.INVALID_CODE')),
  });

  type InitialValue = Yup.InferType<typeof ValidationScheme>;

  const initialValues: InitialValue = {
    email: email,
    code: code,
  };

  return (
    <Styled.Container>
      <Styled.SubTitle>
        {t('RECOVERY_PASS_SCREEN.TYPE_THE_CODE')}
      </Styled.SubTitle>

      <Formik
        initialValues={initialValues}
        enableReinitialize
        validationSchema={ValidationScheme}
        onSubmit={(values) => {
          handleSubmit(values.email, values.code);
        }}
      >
        {(props) => (
          <Styled.Form onSubmit={props.submitForm}>
            <Styled.Field
              label={t('RECOVERY_PASS_SCREEN.EMAIL')}
              ariaLabel={t('RECOVERY_PASS_SCREEN.ARIA_INPUT_EMAIL')}
              name="email"
              type="email"
            />

            <Styled.Field
              label={t('CODE')}
              ariaLabel={t('RECOVERY_PASS_SCREEN.ARIA_CODE')}
              name="code"
              type="text"
            />

            <Styled.Submit
              isDisabled={!props.isValid}
              text={t('RECOVERY_PASS_SCREEN.CHECK_CODE')}
              type="submit"
              rounded
            />

            <Styled.BackToLogin
              onClick={() => history.push('/auth')}
              text={t('RECOVERY_PASS_SCREEN.BACK')}
              rounded
              outline
            />
          </Styled.Form>
        )}
      </Formik>
    </Styled.Container>
  );
}

export default CheckCode;
