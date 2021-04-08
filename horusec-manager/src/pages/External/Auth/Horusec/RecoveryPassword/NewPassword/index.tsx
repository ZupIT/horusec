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
import queryString from 'query-string';
import accountService from 'services/account';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { Dialog } from 'components';
import {
  hasLowerCase,
  hasNumber,
  hasSpecialCharacter,
  hasUpperCase,
} from 'helpers/validators';
import * as Yup from 'yup';
import { Formik } from 'formik';

function NewPasswordScreen() {
  const { t } = useTranslation();
  const history = useHistory();
  const { dispatchMessage } = useResponseMessage();
  const [token, setToken] = useState('');

  const [passValidations, setPassValidations] = useState({
    alpha: false,
    number: false,
    minCharacters: false,
    characterSpecial: false,
  });
  const [successDialogVisible, setSuccessDialogVisisible] = useState(false);

  useEffect(() => {
    const params = queryString.parse(window.location.search);

    if (params?.token) {
      const value = params?.token as string;
      setToken(value);
    } else {
      history.replace('/auth/recovery-password');
    }
  }, [history]);

  const handleSubmit = (password: string, confirmPass: string) => {
    if (password && confirmPass) {
      accountService
        .changePassword(token, password)
        .then(() => {
          setSuccessDialogVisisible(true);
        })
        .catch((err) => {
          dispatchMessage(err?.response?.data);
        });
    }
  };

  const ValidationScheme = Yup.object({
    password: Yup.string()
      .min(8, t('RECOVERY_PASS_SCREEN.MIN_CHARACTERS'))
      .test(
        'regex',
        t('RECOVERY_PASS_SCREEN.ALPHA_REQUIREMENTS'),
        (value) => hasUpperCase(value) && hasLowerCase(value)
      )
      .test(
        'regex',
        t('RECOVERY_PASS_SCREEN.SPECIAL_CHARACTER'),
        hasSpecialCharacter
      )
      .test('regex', t('RECOVERY_PASS_SCREEN.NUMBER_REQUIREMENT'), hasNumber)
      .required(t('RECOVERY_PASS_SCREEN.INVALID_PASS')),
    confirmPass: Yup.string()
      .oneOf(
        [Yup.ref('password')],
        t('RECOVERY_PASS_SCREEN.INVALID_CONFIRM_PASS')
      )
      .required(t('RECOVERY_PASS_SCREEN.INVALID_CONFIRM_PASS')),
  });

  type InitialValue = Yup.InferType<typeof ValidationScheme>;

  const initialValues: InitialValue = {
    password: '',
    confirmPass: '',
  };

  const handlePasswordValue = (field: string) => {
    setPassValidations({
      minCharacters: field.length < 8,
      alpha: !hasUpperCase(field) || !hasLowerCase(field),
      number: !hasNumber(field),
      characterSpecial: !hasSpecialCharacter(field),
    });
  };

  return (
    <Styled.Container>
      <Styled.SubTitle>
        {t('RECOVERY_PASS_SCREEN.CREATE_NEW_PASS')}
      </Styled.SubTitle>

      <Styled.PassRequirements>
        <Styled.Info>
          {t('RECOVERY_PASS_SCREEN.PASSWORD_REQUIREMENTS')}
        </Styled.Info>

        <Styled.Item isInvalid={passValidations.minCharacters}>
          {t('RECOVERY_PASS_SCREEN.MIN_CHARACTERS')}
        </Styled.Item>

        <Styled.Item isInvalid={passValidations.alpha}>
          {t('RECOVERY_PASS_SCREEN.ALPHA_REQUIREMENTS')}
        </Styled.Item>

        <Styled.Item isInvalid={passValidations.number}>
          {t('RECOVERY_PASS_SCREEN.NUMBER_REQUIREMENT')}
        </Styled.Item>

        <Styled.Item isInvalid={passValidations.characterSpecial}>
          {t('RECOVERY_PASS_SCREEN.SPECIAL_CHARACTER')}
        </Styled.Item>

        <Styled.Info>{t('RECOVERY_PASS_SCREEN.NO_EQUALS')}</Styled.Info>

        <Styled.Item>{t('RECOVERY_PASS_SCREEN.USER_NAME')}</Styled.Item>
      </Styled.PassRequirements>

      <Formik
        initialValues={initialValues}
        validationSchema={ValidationScheme}
        validate={(values) => handlePasswordValue(values.password)}
        onSubmit={(values) => {
          handleSubmit(values.password, values.confirmPass);
        }}
      >
        {(props) => (
          <Styled.Form onSubmit={props.submitForm}>
            <Styled.Field
              label={t('RECOVERY_PASS_SCREEN.PASSWORD')}
              name="password"
              type="password"
            />

            <Styled.Field
              label={t('RECOVERY_PASS_SCREEN.CONFIRM_PASS')}
              name="confirm-pass"
              type="password"
            />

            <Styled.Submit
              isDisabled={!props.isValid}
              text={t('RECOVERY_PASS_SCREEN.UPDATE_PASS')}
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

      <Dialog
        isVisible={successDialogVisible}
        confirmText={t('RECOVERY_PASS_SCREEN.BACK')}
        message={t('RECOVERY_PASS_SCREEN.SUCCESS_ALTER_PASS')}
        onConfirm={() => history.push('/auth')}
      />
    </Styled.Container>
  );
}

export default NewPasswordScreen;
