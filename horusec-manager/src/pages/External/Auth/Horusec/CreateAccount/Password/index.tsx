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

function PasswordForm() {
  const { t } = useTranslation();
  const { disabledBroker } = getCurrentConfig();
  const history = useHistory();
  const {
    password,
    setPassword,
    confirmPass,
    setConfirmPass,
    isLoading,
    createAccount,
    successDialogVisible,
  } = useContext(CreateAccountContext);

  const [passValidations, setPassValidations] = useState({
    alpha: false,
    number: false,
    minCharacters: false,
    characterSpecial: false,
  });

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    createAccount();
  };

  const validateEqualsPassword = (value: string) => {
    return value === password.value;
  };

  const handlePasswordValue = (field: Field) => {
    setPassValidations({
      minCharacters: field.value.length < 8,
      alpha: !hasUpperCase(field.value) || !hasLowerCase(field.value),
      number: !hasNumber(field.value),
      characterSpecial: !hasSpecialCharacter(field.value),
    });

    setPassword(field);
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

      <Styled.Form onSubmit={handleSubmit}>
        <Styled.Field
          onChangeValue={(field: Field) => handlePasswordValue(field)}
          label={t('CREATE_ACCOUNT_SCREEN.PASSWORD')}
          name="password"
          type="password"
          invalidMessage={t('CREATE_ACCOUNT_SCREEN.INVALID_PASS')}
          validation={isEmptyString}
        />

        <Styled.Field
          label={t('CREATE_ACCOUNT_SCREEN.CONFIRM_PASS')}
          onChangeValue={(field: Field) => setConfirmPass(field)}
          name="confirm-pass"
          type="password"
          invalidMessage={t('CREATE_ACCOUNT_SCREEN.INVALID_CONFIRM_PASS')}
          validation={validateEqualsPassword}
        />

        <Styled.Submit
          isDisabled={
            !confirmPass.isValid ||
            !password.isValid ||
            passValidations.alpha ||
            passValidations.characterSpecial ||
            passValidations.minCharacters ||
            passValidations.number
          }
          text={t('CREATE_ACCOUNT_SCREEN.SUBMIT')}
          type="submit"
          isLoading={isLoading}
          rounded
        />

        <Styled.BackToLogin
          onClick={() => history.push('/auth')}
          text={t('CREATE_ACCOUNT_SCREEN.BACK')}
          outline
          rounded
        />
      </Styled.Form>

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
