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
import { Dialog, Select, Icon } from 'components';
import { useTranslation } from 'react-i18next';
import { useTheme } from 'styled-components';
import Styled from './styled';
import { Field } from 'helpers/interfaces/Field';
import repositoryService from 'services/repository';
import { getCurrentCompany } from 'helpers/localStorage/currentCompany';
import { Repository } from 'helpers/interfaces/Repository';
import { get } from 'lodash';
import { isValidURL } from 'helpers/validators';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import webhookService from 'services/webhook';
import { Webhook, WebhookHeader } from 'helpers/interfaces/Webhook';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import { cloneDeep } from 'lodash';

interface Props {
  isVisible: boolean;
  onCancel: () => void;
  onConfirm: () => void;
  webhookToEdit: Webhook;
}

const webhookHttpMethods = [{ value: 'POST' }, { value: 'GET' }];

const AddWebhook: React.FC<Props> = ({
  isVisible,
  onCancel,
  onConfirm,
  webhookToEdit,
}) => {
  const { t } = useTranslation();
  const { colors } = useTheme();
  const { companyID } = getCurrentCompany();

  const { dispatchMessage } = useResponseMessage();
  const { showSuccessFlash } = useFlashMessage();

  const [isLoading, setLoading] = useState(false);
  const [httpMethod, setHttpMethod] = useState(webhookToEdit?.method);
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [selectedRepository, setSelectedRepository] = useState<Repository>(
    webhookToEdit?.repository
  );
  const [url, setUrl] = useState<Field>({
    value: webhookToEdit?.url,
    isValid: false,
  });
  const [headers, setHeaders] = useState<WebhookHeader[]>([
    { key: '', value: '' },
  ]);
  const [description, setDescription] = useState<Field>({
    value: webhookToEdit?.description,
    isValid: false,
  });

  const handleConfirmSave = () => {
    setLoading(true);

    webhookService
      .update(
        companyID,
        selectedRepository.repositoryID,
        webhookToEdit.webhookID,
        url.value,
        httpMethod,
        headers,
        description.value
      )
      .then(() => {
        showSuccessFlash(t('WEBHOOK_SCREEN.SUCCESS_UPDATE'));
        onConfirm();
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      })
      .finally(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    const fetchRepositories = () => {
      repositoryService.getAll(companyID).then((result) => {
        setRepositories(result.data.content);
      });
    };

    fetchRepositories();
  }, [companyID]);

  useEffect(() => {
    if (webhookToEdit) {
      const { url, headers, description, method, repository } = webhookToEdit;

      setDescription({ isValid: true, value: description });
      setUrl({ isValid: true, value: url });
      setSelectedRepository(repository);
      setHttpMethod(method);
      setHeaders(headers);
    }
  }, [webhookToEdit]);

  const handleSetHeader = (index: number, key: string, value: string) => {
    const headersCopy = cloneDeep(headers);
    const header = { key, value };
    headersCopy[index] = header;
    setHeaders(headersCopy);
  };

  return (
    <Dialog
      isVisible={isVisible}
      message={t('WEBHOOK_SCREEN.ADD')}
      onCancel={onCancel}
      onConfirm={handleConfirmSave}
      confirmText={t('WEBHOOK_SCREEN.SAVE')}
      disableConfirm={!url.isValid || !selectedRepository}
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
          initialValue={description.value}
          name="description"
          type="text"
          width="100%"
        />

        <Styled.Label>{t('WEBHOOK_SCREEN.RESPOSITORY_LABEL')}</Styled.Label>

        <Select
          keyLabel="name"
          width="100%"
          options={repositories}
          initialValue={webhookToEdit?.repository}
          title={t('WEBHOOK_SCREEN.REPOSITORY')}
          onChangeValue={(value) => setSelectedRepository(value)}
        />

        <Styled.Label>{t('WEBHOOK_SCREEN.URL_LABEL')}</Styled.Label>

        <Styled.Wrapper>
          <Styled.URLSelect
            keyLabel="value"
            keyValue="value"
            width="100px"
            initialValue={webhookHttpMethods[0]}
            options={webhookHttpMethods}
            onChangeValue={(item) => setHttpMethod(item.value)}
            rounded
            disabled
            color={get(colors.methods, httpMethod?.toLocaleLowerCase())}
          />

          <Styled.Field
            label={t('WEBHOOK_SCREEN.URL')}
            onChangeValue={(field: Field) => setUrl(field)}
            name="url"
            type="text"
            width="400px"
            validation={isValidURL}
            invalidMessage={t('WEBHOOK_SCREEN.INVALID_URL')}
            initialValue={url.value}
          />
        </Styled.Wrapper>

        <Styled.Label>{t('WEBHOOK_SCREEN.HEADERS_LABEL')}</Styled.Label>

        {webhookToEdit?.headers?.map((header, index) => (
          <Styled.Wrapper key={index}>
            <Styled.Field
              label={t('WEBHOOK_SCREEN.KEY')}
              name="key"
              onChangeValue={({ value }) =>
                handleSetHeader(index, value, headers[index].value)
              }
              width="200px"
              initialValue={headers[index]?.key}
            />

            <Styled.Field
              label={t('WEBHOOK_SCREEN.VALUE')}
              name="value"
              type="text"
              onChangeValue={({ value }) =>
                handleSetHeader(index, headers[index].key, value)
              }
              width="200px"
              initialValue={headers[index]?.value}
            />

            {index + 1 === headers?.length && headers?.length !== 3 ? (
              <Icon
                name="plus"
                size="20px"
                onClick={() => setHeaders([...headers, { key: '', value: '' }])}
              />
            ) : null}
          </Styled.Wrapper>
        ))}
      </Styled.Form>
    </Dialog>
  );
};

export default AddWebhook;
