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
import { Calendar, Checkbox, Dialog } from 'components';
import { useTranslation } from 'react-i18next';
import Styled from './styled';
import { isEmptyString } from 'helpers/validators';
import { Field } from 'helpers/interfaces/Field';
import { useTheme } from 'styled-components';
import companyService from 'services/company';
import useResponseMessage from 'helpers/hooks/useResponseMessage';

import SuccessAddToken from './Success';
import { Workspace } from 'helpers/interfaces/Workspace';
import validateExpiresAt from 'helpers/validators/validateExpiresAt';

interface Props {
  isVisible: boolean;
  onCancel: () => void;
  onConfirm: () => void;
  selectedWorkspace: Workspace;
}

const INITIAL_FIELD = {
  value: '',
  isValid: false,
};

const MIN_DATE = new Date(Date.now() + 86400000);

const AddToken: React.FC<Props> = ({
  isVisible,
  onCancel,
  onConfirm,
  selectedWorkspace,
}) => {
  const { t } = useTranslation();
  const { colors } = useTheme();
  const { dispatchMessage } = useResponseMessage();

  const [isLoading, setLoading] = useState(false);
  const [tokenCreated, setTokenCreated] = useState<string>(null);
  const [isExpirable, setIsExpirable] = useState(false);
  const [description, setDescription] = useState<Field>(INITIAL_FIELD);
  const [expiresAt, setExpiresAt] = useState<Date>(MIN_DATE);

  const resetFields = () => {
    setDescription(INITIAL_FIELD);
    setExpiresAt(MIN_DATE);
    setIsExpirable(false);
  };

  const handleConfirmSave = () => {
    if (description.isValid) {
      setLoading(true);

      const data = {
        description: description.value,
        isExpirable: isExpirable,
        expiresAt: expiresAt,
      };

      if (isExpirable === false) {
        delete data.isExpirable;
        delete data.expiresAt;
      }

      companyService
        .createToken(selectedWorkspace.companyID, data)
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

  useEffect(() => {
    if (isExpirable === false) {
      setExpiresAt(MIN_DATE);
    }
  }, [isExpirable, expiresAt]);

  return (
    <>
      <Dialog
        isVisible={isVisible}
        message={t('WORKSPACES_SCREEN.CREATE_NEW_TOKEN')}
        onCancel={() => {
          onCancel();
          resetFields();
        }}
        onConfirm={handleConfirmSave}
        confirmText={t('WORKSPACES_SCREEN.SAVE')}
        disableConfirm={!description.isValid}
        disabledColor={colors.button.disableInDark}
        loadingConfirm={isLoading}
        width={600}
        defaultButton
        hasCancel
      >
        <Styled.SubTitle>
          {t('WORKSPACES_SCREEN.CREATE_TOKEN_BELOW')}
        </Styled.SubTitle>

        <Styled.Field
          label={t('WORKSPACES_SCREEN.DESCRIPTION')}
          invalidMessage={t('WORKSPACES_SCREEN.INVALID_DESCRIPTION')}
          onChangeValue={(field: Field) => setDescription(field)}
          validation={isEmptyString}
          name="description"
          type="text"
          width="100%"
        />

        <Styled.ContainerCheckbox>
          <Checkbox
            disabled={false}
            initialValue={isExpirable}
            onChangeValue={(field) => setIsExpirable(field)}
            label={t('REPOSITORIES_SCREEN.IS_EXPIRABLE')}
          />
        </Styled.ContainerCheckbox>

        {isExpirable ? (
          <Calendar
            initialDate={expiresAt}
            title={t('REPOSITORIES_SCREEN.EXPIRES_AT')}
            onChangeValue={(field) => setExpiresAt(field.value)}
            minDate={MIN_DATE}
            validation={validateExpiresAt}
            invalidMessage={t('REPOSITORIES_SCREEN.INVALID_EXPIRES_AT')}
          />
        ) : null}
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
