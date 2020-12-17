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
import useWorkspace from 'helpers/hooks/useWorkspace';

interface Props {
  isVisible: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

const AddRepository: React.FC<Props> = ({ isVisible, onCancel, onConfirm }) => {
  const { t } = useTranslation();
  const { colors } = useTheme();
  const { currentWorkspace } = useWorkspace();
  const { dispatchMessage } = useResponseMessage();
  const { showSuccessFlash } = useFlashMessage();

  const [isLoading, setLoading] = useState(false);
  const [name, setName] = useState<Field>({ value: '', isValid: false });
  const [description, setDescription] = useState<Field>({
    value: '',
    isValid: false,
  });

  const [adminGroup, setAdminGroup] = useState<Field>({
    isValid: false,
    value: currentWorkspace?.authzAdmin,
  });

  const [supervisorGroup, setSupervisorGroup] = useState<Field>({
    isValid: false,
    value: currentWorkspace?.authzAdmin,
  });

  const [userGroup, setUserGroup] = useState<Field>({
    isValid: false,
    value: currentWorkspace?.authzMember,
  });

  const resetFields = () => {
    const defaultValue = { value: '', isValid: false };
    setDescription(defaultValue);
    setName(defaultValue);
  };

  const handleConfirmSave = () => {
    if (name.isValid) {
      setLoading(true);

      repositoryService
        .create(currentWorkspace.companyID, name.value, description.value, {
          authzAdmin: adminGroup.value,
          authzMember: userGroup.value,
          authzSupervisor: supervisorGroup.value,
        })
        .then(() => {
          onConfirm();
          showSuccessFlash(t('REPOSITORIES_SCREEN.SUCCESS_CREATE_REPO'));
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
      message={t('REPOSITORIES_SCREEN.CREATE_REPO')}
      onCancel={() => {
        onCancel();
        resetFields();
      }}
      onConfirm={handleConfirmSave}
      confirmText={t('REPOSITORIES_SCREEN.SAVE')}
      disableConfirm={!name.isValid}
      disabledColor={colors.button.disableInDark}
      loadingConfirm={isLoading}
      width={600}
      hasCancel
    >
      <Styled.Form onSubmit={handleConfirmSave}>
        <Styled.Field
          label={t('REPOSITORIES_SCREEN.NAME_REPO')}
          invalidMessage={t('REPOSITORIES_SCREEN.INVALID_NAME')}
          onChangeValue={(field: Field) => setName(field)}
          validation={isEmptyString}
          name="name"
          type="text"
          width="100%"
        />

        <Styled.Field
          label={t('REPOSITORIES_SCREEN.DESCRIPTION_REPO')}
          onChangeValue={(field: Field) => setDescription(field)}
          name="description"
          type="text"
          width="100%"
        />

        {getCurrentConfig().authType === authTypes.LDAP ? (
          <>
            <Styled.SubTitle>
              {t('REPOSITORIES_SCREEN.REFERENCE_GROUP')}
            </Styled.SubTitle>

            <Styled.Wrapper>
              <Styled.Label>{t('REPOSITORIES_SCREEN.ADMIN')}</Styled.Label>

              <Input
                label={t('REPOSITORIES_SCREEN.GROUP_NAME')}
                onChangeValue={(field: Field) => setAdminGroup(field)}
                initialValue={adminGroup.value}
                name="adminGroup"
                type="text"
                width="100%"
              />
            </Styled.Wrapper>

            <Styled.Wrapper>
              <Styled.Label>{t('REPOSITORIES_SCREEN.SUPERVISOR')}</Styled.Label>

              <Input
                label={t('REPOSITORIES_SCREEN.GROUP_NAME')}
                onChangeValue={(field: Field) => setSupervisorGroup(field)}
                initialValue={supervisorGroup.value}
                name="supervisorGroup"
                type="text"
                width="100%"
              />
            </Styled.Wrapper>

            <Styled.Wrapper>
              <Styled.Label>{t('REPOSITORIES_SCREEN.USER')}</Styled.Label>

              <Input
                label={t('REPOSITORIES_SCREEN.GROUP_NAME')}
                onChangeValue={(field: Field) => setUserGroup(field)}
                initialValue={userGroup.value}
                name="userGroup"
                type="text"
                width="100%"
              />
            </Styled.Wrapper>
          </>
        ) : null}
      </Styled.Form>
    </Dialog>
  );
};

export default AddRepository;
