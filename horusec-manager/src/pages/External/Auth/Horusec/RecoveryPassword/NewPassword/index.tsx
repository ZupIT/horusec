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

import React, { FormEvent, useState, useEffect } from 'react';
import Styled from './styled';
import { useHistory } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Field } from 'helpers/interfaces/Field';
import queryString from 'query-string';
import accountService from 'services/account';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { Dialog } from 'components';
import {
  isEmptyString,
  hasLowerCase,
  hasNumber,
  hasSpecialCharacter,
  hasUpperCase,
} from 'helpers/validators';

function NewPasswordScreen() {
  const { t } = useTranslation();
  const history = useHistory();
  const { dispatchMessage } = useResponseMessage();
  const [token, setToken] = useState('');
  const [password, setPassword] = useState<Field>({
    value: '',
    isValid: false,
  });
  const [confirmPass, setConfirmPass] = useState<Field>({
    value: '',
    isValid: false,
  });
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
      history.replace('/recovery-password');
    }
  }, [history]);

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (password.isValid && confirmPass.isValid) {
      accountService
        .changePassword(token, password.value)
        .then(() => {
          setSuccessDialogVisisible(true);
        })
        .catch((err) => {
          dispatchMessage(err?.response?.data);
        });
    }
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
    <>
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

      <Styled.Form onSubmit={handleSubmit}>
        <Styled.Field
          onChangeValue={(field: Field) => handlePasswordValue(field)}
          label={t('RECOVERY_PASS_SCREEN.PASSWORD')}
          name="password"
          type="password"
          invalidMessage={t('RECOVERY_PASS_SCREEN.INVALID_PASS')}
          validation={isEmptyString}
        />

        <Styled.Field
          label={t('RECOVERY_PASS_SCREEN.CONFIRM_PASS')}
          onChangeValue={(field: Field) => setConfirmPass(field)}
          name="confirm-pass"
          type="password"
          invalidMessage={t('RECOVERY_PASS_SCREEN.INVALID_CONFIRM_PASS')}
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
          text={t('RECOVERY_PASS_SCREEN.UPDATE_PASS')}
          type="submit"
          rounded
        />

        <Styled.BackToLogin
          onClick={() => history.push('/login')}
          text={t('RECOVERY_PASS_SCREEN.BACK')}
          rounded
          outline
        />
      </Styled.Form>

      <Dialog
        isVisible={successDialogVisible}
        confirmText={t('RECOVERY_PASS_SCREEN.BACK')}
        message={t('RECOVERY_PASS_SCREEN.SUCCESS_ALTER_PASS')}
        onConfirm={() => history.push('/login')}
      />
    </>
  );
}

export default NewPasswordScreen;
