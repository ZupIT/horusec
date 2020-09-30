import React, { useState } from 'react';
import { Dialog, Select, Permissions } from 'components';
import { useTranslation } from 'react-i18next';
import Styled from './styled';
import { isValidEmail } from 'helpers/validators';
import { Field } from 'helpers/interfaces/Field';
import { useTheme } from 'styled-components';
import companyService from 'services/company';
import { getCurrentCompany } from 'helpers/localStorage/currentCompany';
import useResponseMessage from 'helpers/hooks/useResponseMessage';

interface Props {
  isVisible: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

interface Role {
  name: string;
  value: string;
}

const InviteToCompany: React.FC<Props> = ({
  isVisible,
  onCancel,
  onConfirm,
}) => {
  const { t } = useTranslation();
  const { colors } = useTheme();
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

  const [email, setEmail] = useState<Field>({ value: '', isValid: false });
  const [role, setRole] = useState<Role>(roles[0]);

  const resetFields = () => {
    const defaultValue = { value: '', isValid: false };
    setEmail(defaultValue);
    setRole(roles[0]);
  };

  const handleConfirmSave = () => {
    if (email.isValid) {
      setLoading(true);

      companyService
        .createUserInCompany(companyID, email.value, role.value)
        .then(() => {
          onConfirm();
          resetFields();
        })
        .catch((err) => {
          dispatchMessage(err?.response?.data);
        })
        .finally(() => {
          setLoading(false);
        });
    }
  };

  return (
    <Dialog
      isVisible={isVisible}
      message={t('USERS_SCREEN.INVITE')}
      onCancel={() => {
        onCancel();
        resetFields();
      }}
      onConfirm={handleConfirmSave}
      confirmText={t('USERS_SCREEN.SAVE')}
      disableConfirm={!email.isValid}
      disabledColor={colors.button.disableInDark}
      loadingConfirm={isLoading}
      width={450}
      defaultButton
      hasCancel
    >
      <Styled.SubTitle>{t('USERS_SCREEN.INVITE_SUBTITLE')}</Styled.SubTitle>

      <Styled.Field
        label={t('USERS_SCREEN.EMAIL')}
        invalidMessage={t('USERS_SCREEN.INVALID_EMAIL')}
        onChangeValue={(field: Field) => setEmail(field)}
        validation={isValidEmail}
        name="email"
        type="text"
        width="100%"
      />

      <Styled.RoleWrapper>
        <Select
          rounded
          keyLabel="name"
          keyValue="value"
          width="340px"
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

export default InviteToCompany;
