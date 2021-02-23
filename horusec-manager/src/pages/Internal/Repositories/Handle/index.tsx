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
import repositoryService from 'services/repository';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import { getCurrentConfig } from 'helpers/localStorage/horusecConfig';
import { authTypes } from 'helpers/enums/authTypes';
import { getCurrentUser } from 'helpers/localStorage/currentUser';
import { Repository } from 'helpers/interfaces/Repository';
import { cloneDeep } from 'lodash';
import useWorkspace from 'helpers/hooks/useWorkspace';
import { ObjectLiteral } from 'helpers/interfaces/ObjectLiteral';

interface Props {
  isVisible: boolean;
  repositoryToEdit?: Repository;
  onCancel: () => void;
  onConfirm: () => void;
}

const HandleRepository: React.FC<Props> = ({
  isVisible,
  onCancel,
  onConfirm,
  repositoryToEdit,
}) => {
  const { t } = useTranslation();
  const { colors } = useTheme();
  const currentUser = getCurrentUser();
  const { dispatchMessage } = useResponseMessage();
  const { showSuccessFlash } = useFlashMessage();
  const { applicationAdminEnable } = getCurrentConfig();
  const { currentWorkspace } = useWorkspace();

  const [isLoading, setLoading] = useState(false);
  const [name, setName] = useState<Field>({ value: '', isValid: false });
  const [description, setDescription] = useState<Field>({
    value: '',
    isValid: false,
  });

  const [adminGroup, setAdminGroup] = useState<string[]>(['']);
  const [memberGroup, setMemberGroup] = useState<string[]>(['']);
  const [supervisorGroup, setSupervisorGroup] = useState<string[]>(['']);

  const [emailAdmin, setEmailAdmin] = useState<Field>({
    isValid: false,
    value: currentUser.email,
  });

  const setValues = (
    nameToset?: string,
    descToSet?: string,
    adminToSet?: string[],
    memberToSet?: string[],
    supervisorToSet?: string[]
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

    if (!supervisorToSet || supervisorToSet.length === 0) {
      setSupervisorGroup(['']);
    } else {
      setSupervisorGroup(supervisorToSet);
    }
  };

  const clearInputs = () => {
    setValues();
  };

  const handleCreate = () => {
    repositoryService
      .create(currentWorkspace.companyID, name.value, description.value, {
        authzAdmin: adminGroup,
        authzMember: memberGroup,
        authzSupervisor: supervisorGroup,
      })
      .then(() => {
        onConfirm();
        showSuccessFlash(t('REPOSITORIES_SCREEN.SUCCESS_CREATE_REPO'));
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
    repositoryService
      .update(
        repositoryToEdit.companyID,
        repositoryToEdit.repositoryID,
        name.value,
        description.value,
        {
          authzAdmin: adminGroup,
          authzMember: memberGroup,
          authzSupervisor: supervisorGroup,
        }
      )
      .then(() => {
        onConfirm();
        showSuccessFlash(t('REPOSITORIES_SCREEN.SUCCESS_EDIT_REPO'));
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

      repositoryToEdit ? handleEdit() : handleCreate();
    }
  };

  const handleSetGroupValue = (group: string, index: number, value: string) => {
    const allGroups: ObjectLiteral = {
      admin: [adminGroup, setAdminGroup],
      supervisor: [supervisorGroup, setSupervisorGroup],
      member: [memberGroup, setMemberGroup],
    };

    const groupList = allGroups[group][0];
    const groupSetter = allGroups[group][1];
    const copyOfGroup = cloneDeep(groupList);

    copyOfGroup[index] = value.trim();
    groupSetter(copyOfGroup);
  };

  const handleRemoveGroupValue = (group: string) => {
    const allGroups: ObjectLiteral = {
      admin: [adminGroup, setAdminGroup],
      supervisor: [supervisorGroup, setSupervisorGroup],
      member: [memberGroup, setMemberGroup],
    };

    const groupList = allGroups[group][0];
    const groupSetter = allGroups[group][1];
    const copyOfGroup = cloneDeep(groupList);

    copyOfGroup.pop();
    groupSetter(copyOfGroup);
  };

  useEffect(() => {
    setValues(
      repositoryToEdit?.name,
      repositoryToEdit?.description,
      repositoryToEdit?.authzAdmin,
      repositoryToEdit?.authzMember,
      repositoryToEdit?.authzSupervisor
    );

    // eslint-disable-next-line
  }, [repositoryToEdit]);

  return (
    <Dialog
      isVisible={isVisible}
      message={
        repositoryToEdit
          ? t('REPOSITORIES_SCREEN.EDIT_REPO')
          : t('REPOSITORIES_SCREEN.CREATE_REPO')
      }
      onCancel={() => {
        clearInputs();
        onCancel();
      }}
      onConfirm={handleSubmit}
      confirmText={t('REPOSITORIES_SCREEN.SAVE')}
      disableConfirm={!name.isValid}
      disabledColor={colors.button.disableInDark}
      loadingConfirm={isLoading}
      width={600}
      hasCancel
    >
      <Styled.Form onSubmit={handleSubmit}>
        <Styled.Field
          name="name"
          label={t('REPOSITORIES_SCREEN.NAME')}
          width="100%"
          onChangeValue={(field: Field) => setName(field)}
          validation={isEmptyString}
          invalidMessage={t('REPOSITORIES_SCREEN.INVALID_NAME')}
          initialValue={name.value}
        />

        <Styled.Field
          name="description"
          label={t('REPOSITORIES_SCREEN.DESCRIPTION')}
          width="100%"
          onChangeValue={(field: Field) => setDescription(field)}
          initialValue={description.value}
        />

        {applicationAdminEnable ? (
          <Styled.Wrapper>
            <Styled.Label>{t('REPOSITORIES_SCREEN.ADMIN_EMAIL')}</Styled.Label>

            <Input
              name="emailAdmin"
              initialValue={emailAdmin.value}
              label={t('REPOSITORIES_SCREEN.EMAIL')}
              onChangeValue={(field: Field) => setEmailAdmin(field)}
            />
          </Styled.Wrapper>
        ) : null}

        {getCurrentConfig().authType === authTypes.LDAP ? (
          <>
            <Styled.SubTitle>
              {t('REPOSITORIES_SCREEN.REFERENCE_GROUP')}
            </Styled.SubTitle>

            <Styled.WrapperColumn>
              <Styled.Label>{t('REPOSITORIES_SCREEN.ADMIN')}</Styled.Label>
              {adminGroup?.map((_, index) => (
                <Styled.Wrapper key={index}>
                  <Input
                    name={`admin-group-${index}`}
                    initialValue={adminGroup[index]}
                    label={t('REPOSITORIES_SCREEN.GROUP_NAME')}
                    onChangeValue={(field: Field) =>
                      handleSetGroupValue('admin', index, field.value)
                    }
                  />

                  {index + 1 === adminGroup.length &&
                  adminGroup.length !== 1 ? (
                    <Styled.OptionIcon
                      name="delete"
                      size="20px"
                      onClick={() => handleRemoveGroupValue('admin')}
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
              <Styled.Label>{t('REPOSITORIES_SCREEN.MEMBER')}</Styled.Label>
              {memberGroup?.map((_, index) => (
                <Styled.Wrapper key={index}>
                  <Input
                    name={`member-group-${index}`}
                    initialValue={memberGroup[index]}
                    label={t('REPOSITORIES_SCREEN.GROUP_NAME')}
                    onChangeValue={(field: Field) =>
                      handleSetGroupValue('member', index, field.value)
                    }
                  />

                  {index + 1 === memberGroup.length &&
                  memberGroup.length !== 1 ? (
                    <Styled.OptionIcon
                      name="delete"
                      size="20px"
                      onClick={() => handleRemoveGroupValue('member')}
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

            <Styled.WrapperColumn>
              <Styled.Label>{t('REPOSITORIES_SCREEN.SUPERVISOR')}</Styled.Label>
              {supervisorGroup?.map((_, index) => (
                <Styled.Wrapper key={index}>
                  <Input
                    name={`supervisor-group-${index}`}
                    initialValue={supervisorGroup[index]}
                    label={t('REPOSITORIES_SCREEN.GROUP_NAME')}
                    onChangeValue={(field: Field) =>
                      handleSetGroupValue('supervisor', index, field.value)
                    }
                  />

                  {index + 1 === supervisorGroup.length &&
                  supervisorGroup.length !== 1 ? (
                    <Styled.OptionIcon
                      name="delete"
                      size="20px"
                      onClick={() => handleRemoveGroupValue('supervisor')}
                    />
                  ) : null}

                  {index + 1 === supervisorGroup.length &&
                  supervisorGroup.length !== 5 ? (
                    <Styled.OptionIcon
                      name="plus"
                      size="20px"
                      onClick={() =>
                        setSupervisorGroup([...supervisorGroup, ''])
                      }
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

export default HandleRepository;
