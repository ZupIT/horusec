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
import { getCurrentUser } from 'helpers/localStorage/currentUser';
import { isValidEmail } from 'helpers/validators';
import { useTheme } from 'styled-components';

interface Props {
  isVisible: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

const EditAccount: React.FC<Props> = ({ isVisible, onCancel, onConfirm }) => {
  const { t } = useTranslation();
  const { email, username } = getCurrentUser();
  const { colors } = useTheme();
  // const { dispatchMessage } = useResponseMessage();
  // const { showSuccessFlash } = useFlashMessage();

  const [isLoading, setLoading] = useState(false);

  const [nameOfUser, setNameOfUser] = useState<Field>({
    isValid: true,
    value: username,
  });

  const [emailOfUser, setEmailOfUser] = useState<Field>({
    isValid: true,
    value: email,
  });

  const handleCancel = () => {
    onCancel();

    setEmailOfUser({ isValid: true, value: email });
    setNameOfUser({ isValid: true, value: username });
  };

  const handleConfirmSave = () => {
    setLoading(true);

    // companyService
    //   .editUserInCompany(companyID, userToEdit.accountID, role.value)
    //   .then(() => {
    //     showSuccessFlash(t('USERS_SCREEN.EDIT_SUCCESS'));
    //     onConfirm();
    //   })
    //   .catch((err) => {
    //     dispatchMessage(err?.response?.data);
    //   })
    //   .finally(() => {
    //     setLoading(false);
    //   });
  };

  return (
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
  );
};

export default EditAccount;
