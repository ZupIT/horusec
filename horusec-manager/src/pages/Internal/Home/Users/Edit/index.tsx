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
import { Dialog, Select, Permissions } from 'components';
import { useTranslation } from 'react-i18next';
import Styled from './styled';
import companyService from 'services/company';
import { getCurrentCompany } from 'helpers/localStorage/currentCompany';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { Account } from 'helpers/interfaces/Account';

interface Props {
  isVisible: boolean;
  userToEdit: Account;
  onCancel: () => void;
  onConfirm: () => void;
}

interface Role {
  name: string;
  value: string;
}

const EditUserRole: React.FC<Props> = ({
  isVisible,
  userToEdit,
  onCancel,
  onConfirm,
}) => {
  const { t } = useTranslation();
  const { companyID } = getCurrentCompany();
  const { dispatchMessage } = useResponseMessage();

  const roles: Role[] = [
    {
      name: t('PERMISSIONS.ADMIN'),
      value: 'admin',
    },
    {
      name: t('PERMISSIONS.MEMBER'),
      value: 'member',
    },
  ];

  const [isLoading, setLoading] = useState(false);
  const [permissionsIsOpen, setPermissionsIsOpen] = useState(false);

  const [role, setRole] = useState<Role>(roles[0]);

  const handleConfirmSave = () => {
    setLoading(true);

    companyService
      .editUserInCompany(companyID, userToEdit.accountID, role.value)
      .then(() => {
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
      message={t('USERS_SCREEN.EDIT_USER')}
      onCancel={onCancel}
      onConfirm={handleConfirmSave}
      confirmText={t('USERS_SCREEN.SAVE')}
      loadingConfirm={isLoading}
      width={450}
      hasCancel
    >
      <Styled.SubTitle>{t('USERS_SCREEN.EDIT_SUBTITLE')}</Styled.SubTitle>

      <Styled.EmailOfUser>
        {userToEdit?.username} - {userToEdit?.email}
      </Styled.EmailOfUser>

      <Styled.RoleWrapper>
        <Select
          rounded
          keyLabel="name"
          keyValue="value"
          width="340px"
          initialValue={userToEdit?.role}
          options={roles}
          onChangeValue={(item) => setRole(item)}
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
  );
};

export default EditUserRole;
