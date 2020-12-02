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
  getCurrentUser,
  setCurrentUser,
} from 'helpers/localStorage/currentUser';
import { isValidEmail } from 'helpers/validators';
import { useTheme } from 'styled-components';
import accountService from 'services/account';
import useAuth from 'helpers/hooks/useAuth';
import { useHistory } from 'react-router-dom';

interface Props {
  isVisible: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

const EditAccount: React.FC<Props> = ({ isVisible, onCancel, onConfirm }) => {
  const { t } = useTranslation();
  const currentUser = getCurrentUser();
  const { colors } = useTheme();
  const { dispatchMessage } = useResponseMessage();
  const { showSuccessFlash } = useFlashMessage();
  const { logout } = useAuth();
  const history = useHistory();

  const [isLoading, setLoading] = useState(false);
  const [successDialogIsOpen, setSuccessDialogIsOpen] = useState(false);

  const [nameOfUser, setNameOfUser] = useState<Field>({
    isValid: true,
    value: currentUser.username,
  });

  const [emailOfUser, setEmailOfUser] = useState<Field>({
    isValid: true,
    value: currentUser.email,
  });

  const resetFields = () => {
    setEmailOfUser({ isValid: true, value: currentUser.email });
    setNameOfUser({ isValid: true, value: currentUser.username });
  };

  const handleCancel = () => {
    onCancel();
    resetFields();
  };

  const handleConfirmSave = () => {
    if (nameOfUser.isValid && emailOfUser.isValid) {
      setLoading(true);

      accountService
        .update(nameOfUser.value, emailOfUser.value)
        .then(() => {
          if (emailOfUser.value !== currentUser.email) {
            setSuccessDialogIsOpen(true);
          }

          setCurrentUser({
            ...currentUser,
            email: emailOfUser.value,
            username: nameOfUser.value,
          });

          showSuccessFlash(t('SETTINGS_SCREEN.EDIT_SUCCESS'));

          onConfirm();
        })
        .catch((err) => {
          dispatchMessage(err?.response?.data);
        })
        .finally(() => {
          setLoading(false);
        });
    }
  };

  const confirmSuccessChangeEmail = () => {
    setSuccessDialogIsOpen(false);
    logout().then(() => history.replace('/auth'));
  };

  return (
    <>
      <Dialog
        isVisible={isVisible}
        message={t('SETTINGS_SCREEN.EDIT_ACCOUNT')}
        onCancel={handleCancel}
        onConfirm={handleConfirmSave}
        confirmText={t('SETTINGS_SCREEN.SAVE')}
        loadingConfirm={isLoading}
        disabledColor={colors.button.disableInDark}
        width={450}
        disableConfirm={!nameOfUser.isValid || !emailOfUser.isValid}
        hasCancel
      >
        <Styled.Form>
          <Styled.Field
            label={t('SETTINGS_SCREEN.NAME')}
            initialValue={nameOfUser.value}
            name="nome"
            width="100%"
            type="text"
            onChangeValue={(field) => setNameOfUser(field)}
          />

          <Styled.Field
            label={t('SETTINGS_SCREEN.EMAIL')}
            initialValue={emailOfUser.value}
            name="email"
            width="100%"
            type="email"
            onChangeValue={(field) => setEmailOfUser(field)}
            validation={isValidEmail}
            invalidMessage={t('SETTINGS_SCREEN.INVALID_EMAIL')}
          />
        </Styled.Form>
      </Dialog>

      <Dialog
        isVisible={successDialogIsOpen}
        message={t('SETTINGS_SCREEN.SUCCESS_UPDATE')}
        onConfirm={confirmSuccessChangeEmail}
        confirmText={t('SETTINGS_SCREEN.CONFIRM')}
      />
    </>
  );
};

export default EditAccount;
