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
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { Repository } from 'helpers/interfaces/Repository';
import SuccessAddToken from './Sucess';

interface Props {
  isVisible: boolean;
  onCancel: () => void;
  onConfirm: () => void;
  currentRepository: Repository;
}

const AddToken: React.FC<Props> = ({
  isVisible,
  onCancel,
  onConfirm,
  currentRepository,
}) => {
  const { t } = useTranslation();
  const { colors } = useTheme();
  const { dispatchMessage } = useResponseMessage();

  const [isLoading, setLoading] = useState(false);
  const [tokenCreated, setTokenCreated] = useState<string>(null);
  const [description, setDescription] = useState<Field>({
    value: '',
    isValid: false,
  });

  const resetFields = () => {
    const defaultValue = { value: '', isValid: false };
    setDescription(defaultValue);
  };

  const handleConfirmSave = () => {
    if (description.isValid) {
      setLoading(true);

      repositoryService
        .createToken(
          currentRepository.companyID,
          currentRepository.repositoryID,
          description.value
        )
        .then((res) => {
          onConfirm();
          resetFields();
          setTokenCreated(res?.data?.content);
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
    <>
      <Dialog
        isVisible={isVisible}
        message={t('REPOSITORIES_SCREEN.CREATE_NEW_TOKEN')}
        onCancel={() => {
          onCancel();
          resetFields();
        }}
        onConfirm={handleConfirmSave}
        confirmText={t('REPOSITORIES_SCREEN.SAVE')}
        disableConfirm={!description.isValid}
        disabledColor={colors.button.disableInDark}
        loadingConfirm={isLoading}
        width={600}
        hasCancel
      >
        <Styled.SubTitle>
          {t('REPOSITORIES_SCREEN.CREATE_TOKEN_BELOW')}
        </Styled.SubTitle>

        <Styled.Field
          label={t('REPOSITORIES_SCREEN.DESCRIPTION')}
          invalidMessage={t('REPOSITORIES_SCREEN.INVALID_DESCRIPTION')}
          onChangeValue={(field: Field) => setDescription(field)}
          validation={isEmptyString}
          name="description"
          type="text"
          width="100%"
        />
      </Dialog>

      {tokenCreated ? (
        <SuccessAddToken
          tokenValue={tokenCreated}
          onConfirm={() => setTokenCreated(null)}
        />
      ) : null}
    </>
  );
};

export default AddToken;
