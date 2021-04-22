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

import {
  hasLowerCase,
  hasNumber,
  hasSpecialCharacter,
  hasUpperCase,
} from 'helpers/validators';
import { useTheme } from 'styled-components';
import accountService from 'services/account';
import { Formik } from 'formik';
import * as Yup from 'yup';
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
      .required(t('SETTINGS_SCREEN.INVALID_PASS')),
    confirmPass: Yup.string()
      .oneOf(
        [Yup.ref('password')],
        t('CREATE_ACCOUNT_SCREEN.INVALID_CONFIRM_PASS')
      )
      .required(t('SETTINGS_SCREEN.INVALID_CONFIRM_PASS')),
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

  const handleConfirmSave = (password: string) => {
    setLoading(true);

    accountService
      .updatePassword(password)
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
    <Formik
      initialValues={initialValues}
      validationSchema={ValidationScheme}
      validate={(values) => handlePasswordValue(values.password)}
      onSubmit={(values) => {
        handleConfirmSave(values.password);
      }}
    >
      {(props) => (
        <Dialog
          isVisible={isVisible}
          message={t('SETTINGS_SCREEN.CHANGE_PASS')}
          onCancel={() => {
            onCancel();
            props.resetForm();
          }}
          onConfirm={props.submitForm}
          confirmText={t('SETTINGS_SCREEN.SAVE')}
          loadingConfirm={isLoading}
          disabledColor={colors.button.disableInDark}
          width={550}
          disableConfirm={!props.isValid}
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
              name="password"
              type="password"
            />

            <Styled.Field
              label={t('SETTINGS_SCREEN.CONFIRM_PASS')}
              name="confirmPass"
              width="100%"
              type="password"
            />
          </Styled.Form>
        </Dialog>
      )}
    </Formik>
  );
};

export default ChangePassword;
