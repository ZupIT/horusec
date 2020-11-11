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
import { Dialog, Select } from 'components';
import { useTranslation } from 'react-i18next';
import { useTheme } from 'styled-components';
import Styled from './styled';
import { Field } from 'helpers/interfaces/Field';
import repositoryService from 'services/repository';
import { getCurrentCompany } from 'helpers/localStorage/currentCompany';
import { Repository } from 'helpers/interfaces/Repository';
import { get } from 'lodash';
import { isValidURL } from 'helpers/validators';

interface Props {
  isVisible: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

const webhookHttpMethods = [{ value: 'POST' }, { value: 'GET' }];

const AddWebhook: React.FC<Props> = ({ isVisible, onCancel, onConfirm }) => {
  const { t } = useTranslation();
  const { colors } = useTheme();
  const { companyID } = getCurrentCompany();

  const [isLoading, setLoading] = useState(false);
  const [httpMethod, setHttpMethod] = useState(webhookHttpMethods[0].value);
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [url, setUrl] = useState<Field>({ value: '', isValid: false });
  const [description, setDescription] = useState<Field>({
    value: '',
    isValid: false,
  });

  const handleConfirmSave = () => {
    console.log('save');
    onConfirm();
  };

  useEffect(() => {
    const fetchRepositories = () => {
      repositoryService.getAll(companyID).then((result) => {
        setRepositories(result.data.content);
      });
    };

    fetchRepositories();
  }, [companyID]);

  return (
    <Dialog
      isVisible={isVisible}
      message={t('WEBHOOK_SCREEN.ADD')}
      onCancel={onCancel}
      onConfirm={handleConfirmSave}
      confirmText={t('WEBHOOK_SCREEN.SAVE')}
      disableConfirm={false}
      disabledColor={colors.button.disableInDark}
      loadingConfirm={isLoading}
      width={600}
      hasCancel
    >
      <Styled.Form>
        <Styled.Label>{t('WEBHOOK_SCREEN.DESCRIPTION_LABEL')}</Styled.Label>

        <Styled.Field
          label={t('WEBHOOK_SCREEN.DESCRIPTION')}
          onChangeValue={(field: Field) => setDescription(field)}
          name="description"
          type="text"
          width="100%"
        />

        <Styled.Label>{t('WEBHOOK_SCREEN.RESPOSITORY_LABEL')}</Styled.Label>

        <Select
          keyLabel="name"
          width="100%"
          options={repositories}
          title={t('WEBHOOK_SCREEN.REPOSITORY')}
          onChangeValue={(value) => console.log(value)}
        />

        <Styled.Label>{t('WEBHOOK_SCREEN.URL_LABEL')}</Styled.Label>

        <Styled.UrlWrapper>
          <Styled.URLSelect
            keyLabel="value"
            keyValue="value"
            width="100px"
            initialValue={webhookHttpMethods[0]}
            options={webhookHttpMethods}
            onChangeValue={(item) => setHttpMethod(item.value)}
            rounded
            color={get(colors.methods, httpMethod.toLocaleLowerCase())}
          />

          <Styled.Field
            label={t('WEBHOOK_SCREEN.URL')}
            onChangeValue={(field: Field) => setUrl(field)}
            name="url"
            type="text"
            width="400px"
            validation={isValidURL}
            invalidMessage={t('WEBHOOK_SCREEN.INVALID_URL')}
          />
        </Styled.UrlWrapper>
      </Styled.Form>
    </Dialog>
  );
};

export default AddWebhook;
