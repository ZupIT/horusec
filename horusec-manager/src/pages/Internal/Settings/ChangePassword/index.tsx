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

import React, { useState } from 'react';
import { Dialog } from 'components';
import { useTranslation } from 'react-i18next';
import Styled from './styled';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import { Field } from 'helpers/interfaces/Field';
import {
  isEmptyString,
  hasLowerCase,
  hasNumber,
  hasSpecialCharacter,
  hasUpperCase,
} from 'helpers/validators';
import { useTheme } from 'styled-components';
import accountService from 'services/account';

interface Props {
  isVisible: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

const ChangePassword: React.FC<Props> = ({
  isVisible,
  onCancel,
  onConfirm,
}) => {
  const { t } = useTranslation();
  const { colors } = useTheme();
  const { dispatchMessage } = useResponseMessage();
  const { showSuccessFlash } = useFlashMessage();

  const [isLoading, setLoading] = useState(false);

  const [password, setPassword] = useState<Field>({
    isValid: false,
    value: '',
  });

  const [confirmPass, setConfirmPass] = useState<Field>({
    isValid: false,
    value: '',
  });

  const [passValidations, setPassValidations] = useState({
    alpha: false,
    number: false,
    minCharacters: false,
    characterSpecial: false,
  });

  const validateEqualsPassword = (value: string) => {
    return value === password.value;
  };

  const resetFields = () => {
    setConfirmPass({ isValid: false, value: '' });
    setPassword({ isValid: false, value: '' });
    setPassValidations({
      minCharacters: false,
      alpha: false,
      number: false,
      characterSpecial: false,
    });
  };

  const handleCancel = () => {
    onCancel();
    resetFields();
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

  const handleConfirmSave = () => {
    setLoading(true);

    accountService
      .updatePassword(password.value)
      .then(() => {
        showSuccessFlash(t('SETTINGS_SCREEN.EDIT_SUCCESS'));
        onConfirm();
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      })
      .finally(() => {
        setLoading(false);
      });
  };

  return (
    <Dialog
      isVisible={isVisible}
      message={t('SETTINGS_SCREEN.CHANGE_PASS')}
      onCancel={handleCancel}
      onConfirm={handleConfirmSave}
      confirmText={t('SETTINGS_SCREEN.SAVE')}
      loadingConfirm={isLoading}
      disabledColor={colors.button.disableInDark}
      width={550}
      disableConfirm={
        !confirmPass.isValid ||
        !password.isValid ||
        passValidations.alpha ||
        passValidations.characterSpecial ||
        passValidations.minCharacters ||
        passValidations.number
      }
      hasCancel
    >
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

        <Styled.Item>{t('CREATE_ACCOUNT_SCREEN.OLD_PASS')}</Styled.Item>
      </Styled.PassRequirements>

      <Styled.Form>
        <Styled.Field
          label={t('SETTINGS_SCREEN.NEW_PASS')}
          initialValue={password.value}
          name="password"
          width="100%"
          type="password"
          onChangeValue={(field) => handlePasswordValue(field)}
          invalidMessage={t('SETTINGS_SCREEN.INVALID_PASS')}
          validation={isEmptyString}
        />

        <Styled.Field
          label={t('SETTINGS_SCREEN.CONFIRM_PASS')}
          initialValue={confirmPass.value}
          name="confirm-pass"
          width="100%"
          type="password"
          onChangeValue={(field) => setConfirmPass(field)}
          invalidMessage={t('SETTINGS_SCREEN.INVALID_CONFIRM_PASS')}
          validation={validateEqualsPassword}
        />
      </Styled.Form>
    </Dialog>
  );
};

export default ChangePassword;
