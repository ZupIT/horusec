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
      name: t('ADMIN'),
      value: 'admin',
    },
    {
      name: t('MEMBER'),
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
      defaultButton
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
