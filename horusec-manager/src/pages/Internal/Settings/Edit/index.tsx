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
  getCurrentUser,
  setCurrentUser,
} from 'helpers/localStorage/currentUser';
import { useTheme } from 'styled-components';
import accountService from 'services/account';
import useAuth from 'helpers/hooks/useAuth';
import { useHistory } from 'react-router-dom';
import { getCurrentConfig } from 'helpers/localStorage/horusecConfig';
import { Formik } from 'formik';
import * as Yup from 'yup';

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
  const { disabledBroker } = getCurrentConfig();

  const [isLoading, setLoading] = useState(false);
  const [successDialogIsOpen, setSuccessDialogIsOpen] = useState(false);

  const confirmSuccessChangeEmail = () => {
    setSuccessDialogIsOpen(false);
    logout().then(() => history.replace('/auth'));
  };

  const ValidationScheme = Yup.object({
    username: Yup.string().required(),
    email: Yup.string().email(t('SETTINGS_SCREEN.INVALID_EMAIL')).required(),
  });

  type InitialValue = Yup.InferType<typeof ValidationScheme>;

  const initialValues: InitialValue = {
    username: currentUser?.username,
    email: currentUser?.email,
  };

  return (
    <>
      <Formik
        initialValues={initialValues}
        validationSchema={ValidationScheme}
        enableReinitialize
        onSubmit={(values) => {
          const { username, email } = values;
          setLoading(true);

          accountService
            .update(username, email)
            .then(() => {
              if (email !== currentUser.email && !disabledBroker) {
                setSuccessDialogIsOpen(true);
              }

              setCurrentUser({
                ...currentUser,
                email,
                username,
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
        }}
      >
        {(props) => (
          <Dialog
            isVisible={isVisible}
            message={t('SETTINGS_SCREEN.EDIT_ACCOUNT')}
            onCancel={() => {
              onCancel();
              props.resetForm();
            }}
            onConfirm={props.submitForm}
            confirmText={t('SETTINGS_SCREEN.SAVE')}
            loadingConfirm={isLoading}
            disabledColor={colors.button.disableInDark}
            width={450}
            disableConfirm={!props.isValid}
            hasCancel
          >
            <Styled.Form>
              <Styled.Field label={t('SETTINGS_SCREEN.NAME')} name="username" />

              <Styled.Field
                label={t('SETTINGS_SCREEN.EMAIL')}
                name="email"
                type="email"
              />
            </Styled.Form>
          </Dialog>
        )}
      </Formik>

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
