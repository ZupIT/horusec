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

import React, { useState, useEffect } from 'react';
import { Dialog } from 'components';
import { useTranslation } from 'react-i18next';
import Styled from './styled';
import { isEmptyString } from 'helpers/validators';
import { Field } from 'helpers/interfaces/Field';
import { useTheme } from 'styled-components';
import repositoryService from 'services/repository';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { Repository } from 'helpers/interfaces/Repository';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import { getCurrentConfig } from 'helpers/localStorage/horusecConfig';
import { authTypes } from 'helpers/enums/authTypes';

interface Props {
  isVisible: boolean;
  onCancel: () => void;
  onConfirm: () => void;
  repoToEdit: Repository;
}

const EditRepository: React.FC<Props> = ({
  isVisible,
  onCancel,
  onConfirm,
  repoToEdit,
}) => {
  const { t } = useTranslation();
  const { colors } = useTheme();
  const { dispatchMessage } = useResponseMessage();
  const { showSuccessFlash } = useFlashMessage();

  const [isLoading, setLoading] = useState(false);
  const [name, setName] = useState<Field>({
    value: repoToEdit?.name,
    isValid: true,
  });
  const [description, setDescription] = useState<Field>({
    value: repoToEdit?.description,
    isValid: true,
  });

  const [adminGroup, setAdminGroup] = useState<Field>({
    isValid: false,
    value: '',
  });

  const [supervisorGroup, setSupervisorGroup] = useState<Field>({
    isValid: false,
    value: '',
  });

  const [userGroup, setUserGroup] = useState<Field>({
    isValid: false,
    value: '',
  });

  const handleConfirmSave = () => {
    if (name.isValid) {
      setLoading(true);

      // TODO: Remover este console.log
      console.log(supervisorGroup, adminGroup, userGroup);

      repositoryService
        .update(
          repoToEdit.companyID,
          repoToEdit.repositoryID,
          name.value,
          description.value
        )
        .then(() => {
          showSuccessFlash(t('REPOSITORIES_SCREEN.SUCCESS_EDIT_REPO'));
          onConfirm();
        })
        .catch((err) => {
          dispatchMessage(err?.response?.data);
        })
        .finally(() => {
          setLoading(false);
        });
    }
  };

  useEffect(() => {
    if (repoToEdit) {
      setName({ value: repoToEdit?.name, isValid: true });
      setDescription({ value: repoToEdit?.description, isValid: true });
    }
  }, [repoToEdit]);

  return (
    <Dialog
      isVisible={isVisible}
      message={t('REPOSITORIES_SCREEN.EDIT_REPO')}
      onCancel={onCancel}
      onConfirm={handleConfirmSave}
      confirmText={t('REPOSITORIES_SCREEN.SAVE')}
      disableConfirm={!name.isValid}
      disabledColor={colors.button.disableInDark}
      loadingConfirm={isLoading}
      width={600}
      hasCancel
    >
      <Styled.SubTitle>
        {t('REPOSITORIES_SCREEN.EDIT_REPO_BELOW')}
      </Styled.SubTitle>

      <Styled.Form onSubmit={handleConfirmSave}>
        <Styled.Field
          label={t('REPOSITORIES_SCREEN.NAME_REPO')}
          invalidMessage={t('REPOSITORIES_SCREEN.INVALID_NAME')}
          onChangeValue={(field: Field) => setName(field)}
          validation={isEmptyString}
          name="name"
          type="text"
          width="100%"
          initialValue={name.value}
        />

        <Styled.Field
          label={t('REPOSITORIES_SCREEN.DESCRIPTION_REPO')}
          onChangeValue={(field: Field) => setDescription(field)}
          name="description"
          type="text"
          width="100%"
          initialValue={description.value}
        />

        {getCurrentConfig().authType === authTypes.LDAP ? (
          <>
            <Styled.SubTitle>
              {t('REPOSITORIES_SCREEN.REFERENCE_GROUP')}
            </Styled.SubTitle>

            <Styled.Wrapper>
              <Styled.Label>{t('REPOSITORIES_SCREEN.ADMIN')}</Styled.Label>

              <Styled.Field
                label={t('REPOSITORIES_SCREEN.GROUP_NAME')}
                onChangeValue={(field: Field) => setAdminGroup(field)}
                name="adminGroup"
                type="text"
                width="100%"
              />
            </Styled.Wrapper>

            <Styled.Wrapper>
              <Styled.Label>{t('REPOSITORIES_SCREEN.SUPERVISOR')}</Styled.Label>

              <Styled.Field
                label={t('REPOSITORIES_SCREEN.GROUP_NAME')}
                onChangeValue={(field: Field) => setSupervisorGroup(field)}
                name="supervisorGroup"
                type="text"
                width="100%"
              />
            </Styled.Wrapper>

            <Styled.Wrapper>
              <Styled.Label>{t('REPOSITORIES_SCREEN.USER')}</Styled.Label>

              <Styled.Field
                label={t('REPOSITORIES_SCREEN.GROUP_NAME')}
                onChangeValue={(field: Field) => setUserGroup(field)}
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

export default EditRepository;
