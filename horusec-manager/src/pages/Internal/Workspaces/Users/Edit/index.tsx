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
import companyService from 'services/company';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { Account } from 'helpers/interfaces/Account';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import useWorkspace from 'helpers/hooks/useWorkspace';
import SearchSelect from 'components/SearchSelect';
import { Formik } from 'formik';
import * as Yup from 'yup';
interface Props {
  isVisible: boolean;
  userToEdit: Account;
  onCancel: () => void;
  onConfirm: () => void;
}

interface Role {
  label: string;
  value: string;
}

const EditUserRole: React.FC<Props> = ({
  isVisible,
  userToEdit,
  onCancel,
  onConfirm,
}) => {
  const { t } = useTranslation();
  const { currentWorkspace } = useWorkspace();
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
    role: Yup.string().oneOf(['admin', 'member']).required(),
  });

  type InitialValue = Yup.InferType<typeof ValidationScheme>;

  const initialValues: InitialValue = {
    role: userToEdit?.role,
  };

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={ValidationScheme}
      enableReinitialize
      onSubmit={(values, actions) => {
        setLoading(true);

        companyService
          .editUserInCompany(
            currentWorkspace?.companyID,
            userToEdit.accountID,
            values.role
          )
          .then(() => {
            showSuccessFlash(t('WORKSPACES_SCREEN.USERS.EDIT_SUCCESS'));
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
          message={t('WORKSPACES_SCREEN.USERS.EDIT_USER')}
          onCancel={onCancel}
          onConfirm={props.submitForm}
          confirmText={t('WORKSPACES_SCREEN.USERS.SAVE')}
          loadingConfirm={isLoading}
          width={450}
          hasCancel
        >
          <Styled.SubTitle>
            {t('WORKSPACES_SCREEN.USERS.EDIT_SUBTITLE')}
          </Styled.SubTitle>

          <Styled.EmailOfUser>
            {userToEdit?.username} - {userToEdit?.email}
          </Styled.EmailOfUser>

          <Styled.RoleWrapper>
            <SearchSelect
              options={roles}
              label={t('WORKSPACES_SCREEN.USERS.ROLE')}
              name="role"
              width="340px"
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

export default EditUserRole;
