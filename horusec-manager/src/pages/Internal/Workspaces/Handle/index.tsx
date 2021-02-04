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

import React, { useEffect, useState } from 'react';
import { Dialog, Input } from 'components';
import { useTranslation } from 'react-i18next';
import Styled from './styled';
import { isEmptyString } from 'helpers/validators';
import { Field } from 'helpers/interfaces/Field';
import { useTheme } from 'styled-components';
import companyService from 'services/company';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import { getCurrentConfig } from 'helpers/localStorage/horusecConfig';
import { authTypes } from 'helpers/enums/authTypes';
import { getCurrentUser } from 'helpers/localStorage/currentUser';
import { Workspace } from 'helpers/interfaces/Workspace';
import { cloneDeep } from 'lodash';

interface Props {
  isVisible: boolean;
  workspaceToEdit?: Workspace;
  onCancel: () => void;
  onConfirm: () => void;
}

const HandleWorkspace: React.FC<Props> = ({
  isVisible,
  onCancel,
  onConfirm,
  workspaceToEdit,
}) => {
  const { t } = useTranslation();
  const { colors } = useTheme();
  const currentUser = getCurrentUser();
  const { dispatchMessage } = useResponseMessage();
  const { showSuccessFlash } = useFlashMessage();
  const { applicationAdminEnable } = getCurrentConfig();

  const [isLoading, setLoading] = useState(false);
  const [name, setName] = useState<Field>({ value: '', isValid: false });
  const [description, setDescription] = useState<Field>({
    value: '',
    isValid: false,
  });

  const [adminGroup, setAdminGroup] = useState<string[]>(['']);
  const [memberGroup, setMemberGroup] = useState<string[]>(['']);

  const [emailAdmin, setEmailAdmin] = useState<Field>({
    isValid: false,
    value: currentUser.email,
  });

  const setValues = (
    nameToset?: string,
    descToSet?: string,
    adminToSet?: string[],
    memberToSet?: string[]
  ) => {
    setName({ value: nameToset, isValid: nameToset ? true : false });
    setDescription({ value: descToSet, isValid: false });
    setEmailAdmin({ value: currentUser?.email, isValid: false });

    if (!adminToSet || adminToSet.length === 0) {
      setAdminGroup(['']);
    } else {
      setAdminGroup(adminToSet);
    }

    if (!memberToSet || memberToSet.length === 0) {
      setMemberGroup(['']);
    } else {
      setMemberGroup(memberToSet);
    }
  };

  const clearInputs = () => {
    setValues();
  };

  const handleCreate = () => {
    companyService
      .create(name.value, description.value, emailAdmin.value, {
        authzAdmin: adminGroup,
        authzMember: memberGroup,
      })
      .then(() => {
        onConfirm();
        showSuccessFlash(t('WORKSPACES_SCREEN.CREATE_SUCCESS'));
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      })
      .finally(() => {
        setLoading(false);
        clearInputs();
      });
  };

  const handleEdit = () => {
    companyService
      .update(
        workspaceToEdit.companyID,
        name.value,
        description.value,
        emailAdmin.value,
        {
          authzAdmin: adminGroup,
          authzMember: memberGroup,
        }
      )
      .then(() => {
        onConfirm();
        showSuccessFlash(t('WORKSPACES_SCREEN.UPDATE_SUCCESS'));
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      })
      .finally(() => {
        setLoading(false);
        clearInputs();
      });
  };

  const handleSubmit = () => {
    if (name.isValid) {
      setLoading(true);

      workspaceToEdit ? handleEdit() : handleCreate();
    }
  };

  const handleSetAdminGroup = (index: number, value: string) => {
    const adminGroupCopy = cloneDeep(adminGroup);
    adminGroupCopy[index] = value;
    setAdminGroup(adminGroupCopy);
  };

  const handleRemoveAdminGroup = () => {
    const adminGroupCopy = cloneDeep(adminGroup);
    adminGroupCopy.pop();
    setAdminGroup(adminGroupCopy);
  };

  const handleRemoveMemberGroup = () => {
    const memberGroupCopy = cloneDeep(memberGroup);
    memberGroupCopy.pop();
    setMemberGroup(memberGroupCopy);
  };

  const handleSetMemberGroup = (index: number, value: string) => {
    const memberGroupCopy = cloneDeep(memberGroup);
    memberGroupCopy[index] = value;
    setMemberGroup(memberGroupCopy);
  };

  useEffect(() => {
    setValues(
      workspaceToEdit?.name,
      workspaceToEdit?.description,
      workspaceToEdit?.authzAdmin,
      workspaceToEdit?.authzMember
    );

    // eslint-disable-next-line
  }, [workspaceToEdit]);

  return (
    <Dialog
      isVisible={isVisible}
      message={
        workspaceToEdit
          ? t('WORKSPACES_SCREEN.EDIT_WORKSPACE')
          : t('WORKSPACES_SCREEN.ADD')
      }
      onCancel={() => {
        clearInputs();
        onCancel();
      }}
      onConfirm={handleSubmit}
      confirmText={t('WORKSPACES_SCREEN.SAVE')}
      disableConfirm={!name.isValid}
      disabledColor={colors.button.disableInDark}
      loadingConfirm={isLoading}
      width={600}
      hasCancel
    >
      <Styled.Form onSubmit={handleSubmit}>
        <Styled.Field
          name="name"
          label={t('WORKSPACES_SCREEN.TABLE.NAME')}
          width="100%"
          onChangeValue={(field: Field) => setName(field)}
          validation={isEmptyString}
          invalidMessage={t('WORKSPACES_SCREEN.INVALID_WORKSPACE_NAME')}
          initialValue={name.value}
        />

        <Styled.Field
          name="description"
          label={t('WORKSPACES_SCREEN.TABLE.DESCRIPTION')}
          width="100%"
          onChangeValue={(field: Field) => setDescription(field)}
          initialValue={description.value}
        />

        {applicationAdminEnable ? (
          <Styled.Wrapper>
            <Styled.Label>{t('WORKSPACES_SCREEN.ADMIN_EMAIL')}</Styled.Label>

            <Input
              name="emailAdmin"
              initialValue={emailAdmin.value}
              label={t('WORKSPACES_SCREEN.EMAIL')}
              onChangeValue={(field: Field) => setEmailAdmin(field)}
            />
          </Styled.Wrapper>
        ) : null}

        {getCurrentConfig().authType === authTypes.LDAP ? (
          <>
            <Styled.SubTitle>
              {t('WORKSPACES_SCREEN.REFERENCE_GROUP')}
            </Styled.SubTitle>

            <Styled.WrapperColumn>
              <Styled.Label>{t('WORKSPACES_SCREEN.ADMIN')}</Styled.Label>
              {adminGroup?.map((_, index) => (
                <Styled.Wrapper key={index}>
                  <Input
                    name={`admin-group-${index}`}
                    initialValue={adminGroup[index]}
                    label={t('WORKSPACES_SCREEN.GROUP_NAME')}
                    onChangeValue={(field: Field) =>
                      handleSetAdminGroup(index, field.value)
                    }
                  />

                  {index + 1 === adminGroup.length &&
                  adminGroup.length !== 1 ? (
                    <Styled.OptionIcon
                      name="delete"
                      size="20px"
                      onClick={handleRemoveAdminGroup}
                    />
                  ) : null}

                  {index + 1 === adminGroup.length &&
                  adminGroup.length !== 5 ? (
                    <Styled.OptionIcon
                      name="plus"
                      size="20px"
                      onClick={() => setAdminGroup([...adminGroup, ''])}
                    />
                  ) : null}
                </Styled.Wrapper>
              ))}
            </Styled.WrapperColumn>

            <Styled.WrapperColumn>
              <Styled.Label>{t('WORKSPACES_SCREEN.MEMBER')}</Styled.Label>
              {memberGroup?.map((_, index) => (
                <Styled.Wrapper key={index}>
                  <Input
                    name={`admin-group-${index}`}
                    initialValue={memberGroup[index]}
                    label={t('WORKSPACES_SCREEN.GROUP_NAME')}
                    onChangeValue={(field: Field) =>
                      handleSetMemberGroup(index, field.value)
                    }
                  />

                  {index + 1 === memberGroup.length &&
                  memberGroup.length !== 1 ? (
                    <Styled.OptionIcon
                      name="delete"
                      size="20px"
                      onClick={handleRemoveMemberGroup}
                    />
                  ) : null}

                  {index + 1 === memberGroup.length &&
                  memberGroup.length !== 5 ? (
                    <Styled.OptionIcon
                      name="plus"
                      size="20px"
                      onClick={() => setMemberGroup([...memberGroup, ''])}
                    />
                  ) : null}
                </Styled.Wrapper>
              ))}
            </Styled.WrapperColumn>
          </>
        ) : null}
      </Styled.Form>
    </Dialog>
  );
};

export default HandleWorkspace;
