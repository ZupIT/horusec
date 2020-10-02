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
import { isEmptyString } from 'helpers/validators';
import { Field } from 'helpers/interfaces/Field';
import { useTheme } from 'styled-components';
import repositoryService from 'services/repository';
import { getCurrentCompany } from 'helpers/localStorage/currentCompany';
import useResponseMessage from 'helpers/hooks/useResponseMessage';

interface Props {
  isVisible: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

const AddRepository: React.FC<Props> = ({ isVisible, onCancel, onConfirm }) => {
  const { t } = useTranslation();
  const { colors } = useTheme();
  const { companyID } = getCurrentCompany();
  const { dispatchMessage } = useResponseMessage();

  const [isLoading, setLoading] = useState(false);
  const [name, setName] = useState<Field>({ value: '', isValid: false });
  const [description, setDescription] = useState<Field>({
    value: '',
    isValid: false,
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
        .create(companyID, name.value, description.value)
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
      defaultButton
      hasCancel
    >
      <Styled.SubTitle>
        {t('REPOSITORIES_SCREEN.CREATE_NEW_REPO')}
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
        />

        <Styled.Field
          label={t('REPOSITORIES_SCREEN.DESCRIPTION_REPO')}
          onChangeValue={(field: Field) => setDescription(field)}
          name="description"
          type="text"
          width="100%"
        />
      </Styled.Form>
    </Dialog>
  );
};

export default AddRepository;
