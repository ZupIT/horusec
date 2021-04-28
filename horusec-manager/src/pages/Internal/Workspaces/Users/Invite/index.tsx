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
import { Dialog, Permissions } from 'components';
import { useTranslation } from 'react-i18next';
import Styled from './styled';
import { useTheme } from 'styled-components';
import companyService from 'services/company';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import { Workspace } from 'helpers/interfaces/Workspace';
import * as Yup from 'yup';
import { Formik } from 'formik';
import SearchSelect from 'components/SearchSelect';
interface Props {
  isVisible: boolean;
  onCancel: () => void;
  onConfirm: () => void;
  selectedWorkspace: Workspace;
}

interface Role {
  label: string;
  value: string;
}

const InviteToCompany: React.FC<Props> = ({
  isVisible,
  onCancel,
  onConfirm,
  selectedWorkspace,
}) => {
  const { t } = useTranslation();
  const { colors } = useTheme();
  const { dispatchMessage } = useResponseMessage();
  const { showSuccessFlash } = useFlashMessage();

  const roles: Role[] = [
    {
      label: t('PERMISSIONS.ADMIN'),
      value: 'admin',
    },
    {
      label: t('PERMISSIONS.MEMBER'),
      value: 'member',
    },
  ];

  const [isLoading, setLoading] = useState(false);
  const [permissionsIsOpen, setPermissionsIsOpen] = useState(false);

  const ValidationScheme = Yup.object({
    email: Yup.string()
      .email(t('WORKSPACES_SCREEN.USERS.INVALID_EMAIL'))
      .required(t('WORKSPACES_SCREEN.USERS.INVALID_EMAIL')),
    role: Yup.string().oneOf(['admin', 'member']).required(),
  });

  type InitialValue = Yup.InferType<typeof ValidationScheme>;

  const initialValues: InitialValue = {
    email: '',
    role: '',
  };

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={ValidationScheme}
      onSubmit={(value, actions) => {
        setLoading(true);

        companyService
          .createUserInCompany(
            selectedWorkspace?.companyID,
            value.email,
            value.role
          )
          .then(() => {
            showSuccessFlash(t('WORKSPACES_SCREEN.USERS.INVITE_SUCCESS'));
            onConfirm();
            actions.resetForm();
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
          message={t('WORKSPACES_SCREEN.USERS.INVITE')}
          onCancel={() => {
            onCancel();
            props.resetForm();
          }}
          onConfirm={props.submitForm}
          confirmText={t('WORKSPACES_SCREEN.USERS.SAVE')}
          disableConfirm={!props.isValid}
          disabledColor={colors.button.disableInDark}
          loadingConfirm={isLoading}
          width={450}
          hasCancel
        >
          <Styled.SubTitle>
            {t('WORKSPACES_SCREEN.USERS.INVITE_SUBTITLE')}
          </Styled.SubTitle>

          <Styled.Field
            label={t('WORKSPACES_SCREEN.USERS.EMAIL')}
            name="email"
            type="text"
          />

          <Styled.RoleWrapper>
            <SearchSelect
              options={roles}
              label={t('WORKSPACES_SCREEN.USERS.ROLE')}
              name="role"
              width="350px"
            />

            <Styled.HelpIcon
              name="help"
              size="20px"
              onClick={() => setPermissionsIsOpen(true)}
            />
          </Styled.RoleWrapper>

          <Permissions
            isOpen={permissionsIsOpen}
            onClose={() => setPermissionsIsOpen(false)}
            rolesType="COMPANY"
          />
        </Dialog>
      )}
    </Formik>
  );
};

export default InviteToCompany;
