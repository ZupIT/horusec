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

import React, { FormEvent, useState, useContext } from 'react';
import Styled from './styled';
import { useHistory } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Field } from 'helpers/interfaces/Field';
import { Dialog } from 'components';
import {
  isEmptyString,
  hasLowerCase,
  hasNumber,
  hasSpecialCharacter,
  hasUpperCase,
} from 'helpers/validators';
import { CreateAccountContext } from 'contexts/CreateAccount';
import { getCurrentConfig } from 'helpers/localStorage/horusecConfig';
import * as Yup from 'yup';
import { Formik, useField } from 'formik';

function PasswordForm() {
  const { t } = useTranslation();
  const { disabledBroker } = getCurrentConfig();
  const history = useHistory();
  const { isLoading, createAccount, successDialogVisible } = useContext(
    CreateAccountContext
  );

  const [passValidations, setPassValidations] = useState({
    alpha: false,
    number: false,
    minCharacters: false,
    characterSpecial: false,
  });

  const ValidationScheme = Yup.object({
    password: Yup.string()
      .min(8, t('CREATE_ACCOUNT_SCREEN.MIN_CHARACTERS'))
      .test(
        'regex',
        t('CREATE_ACCOUNT_SCREEN.ALPHA_REQUIREMENTS'),
        (value) => hasUpperCase(value) && hasLowerCase(value)
      )
      .test(
        'regex',
        t('CREATE_ACCOUNT_SCREEN.SPECIAL_CHARACTER'),
        hasSpecialCharacter
      )
      .test('regex', t('CREATE_ACCOUNT_SCREEN.NUMBER_REQUIREMENT'), hasNumber)
      .required(),
    confirmPass: Yup.string()
      .oneOf(
        [Yup.ref('password')],
        t('CREATE_ACCOUNT_SCREEN.INVALID_CONFIRM_PASS')
      )
      .required(),
  });

  type InitialValue = Yup.InferType<typeof ValidationScheme>;

  const initialValues: InitialValue = {
    password: '',
    confirmPass: '',
  };

  // const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
  //   event.preventDefault();
  //   createAccount();
  // };

  // const validateEqualsPassword = (value: string) => {
  //   return value === password.value;
  // };

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
        {t('CREATE_ACCOUNT_SCREEN.CREATE_NEW_PASS')}
      </Styled.SubTitle>

      <Styled.PassRequirements>
        <Styled.Info>
          {t('CREATE_ACCOUNT_SCREEN.PASSWORD_REQUIREMENTS')}
        </Styled.Info>

        <Styled.Item isInvalid={passValidations.minCharacters}>
          {t('CREATE_ACCOUNT_SCREEN.MIN_CHARACTERS')}
        </Styled.Item>

        <Styled.Item isInvalid={passValidations.alpha}>
          {t('CREATE_ACCOUNT_SCREEN.ALPHA_REQUIREMENTS')}
        </Styled.Item>

        <Styled.Item isInvalid={passValidations.number}>
          {t('CREATE_ACCOUNT_SCREEN.NUMBER_REQUIREMENT')}
        </Styled.Item>

        <Styled.Item isInvalid={passValidations.characterSpecial}>
          {t('CREATE_ACCOUNT_SCREEN.SPECIAL_CHARACTER')}
        </Styled.Item>

        <Styled.Info>{t('CREATE_ACCOUNT_SCREEN.NO_EQUALS')}</Styled.Info>

        <Styled.Item>{t('CREATE_ACCOUNT_SCREEN.USER_NAME')}</Styled.Item>
      </Styled.PassRequirements>

      <Formik
        initialValues={initialValues}
        validationSchema={ValidationScheme}
        validate={(values) => handlePasswordValue(values.password)}
        onSubmit={(values) => {
          createAccount(values.password);
        }}
      >
        {(props) => (
          <Styled.Form>
            <Styled.Field
              label={t('CREATE_ACCOUNT_SCREEN.PASSWORD')}
              name="password"
              type="password"
            />

            <Styled.Field
              label={t('CREATE_ACCOUNT_SCREEN.CONFIRM_PASS')}
              name="confirmPass"
              type="password"
            />

            <Styled.Submit
              isDisabled={!props.isValid}
              text={t('CREATE_ACCOUNT_SCREEN.SUBMIT')}
              type="submit"
              isLoading={isLoading}
              rounded
            />

            <Styled.BackToLogin
              onClick={() => history.push('/auth')}
              text={t('CREATE_ACCOUNT_SCREEN.BACK')}
              type="button"
              outline
              rounded
            />
          </Styled.Form>
        )}
      </Formik>
      <Dialog
        isVisible={successDialogVisible}
        confirmText={t('CREATE_ACCOUNT_SCREEN.CONFIRM')}
        message={
          disabledBroker
            ? t('CREATE_ACCOUNT_SCREEN.SUCCESS_CREATE_ACCOUNT')
            : t('CREATE_ACCOUNT_SCREEN.SUCCESS_CREATE_ACCOUNT_WITH_CONFIRM')
        }
        onConfirm={() => history.push('/auth')}
        roundedButton
      />
    </Styled.Container>
  );
}

export default PasswordForm;
