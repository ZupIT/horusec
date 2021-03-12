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
import { useTranslation } from 'react-i18next';
import Styled from './styled';
import { Button, Dialog, SearchBar, Datatable, Datasource } from 'components';
import { Webhook } from 'helpers/interfaces/Webhook';
import { useTheme } from 'styled-components';
import { get } from 'lodash';
import webhookService from 'services/webhook';

import AddWebhook from './Add';
import EditWebhook from './Edit';

import useResponseMessage from 'helpers/hooks/useResponseMessage';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import useWorkspace from 'helpers/hooks/useWorkspace';

const Webhooks: React.FC = () => {
  const { t } = useTranslation();
  const { colors } = useTheme();
  const { currentWorkspace } = useWorkspace();
  const { dispatchMessage } = useResponseMessage();
  const { showSuccessFlash } = useFlashMessage();

  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [filteredWebhooks, setFilteredWebhooks] = useState<Webhook[]>([]);
  const [webhookToDelete, setWebhookToDelete] = useState<Webhook>();
  const [webhookToEdit, setWebhookToEdit] = useState<Webhook>();
  const [webhookToCopy, setWebhookToCopy] = useState<Webhook>();

  const [isLoading, setLoading] = useState(false);
  const [deleteIsLoading, setDeleteIsLoading] = useState(false);
  const [addWebhookVisible, setAddWebhookVisible] = useState(false);

  const fetchData = () => {
    setLoading(true);

    webhookService
      .getAll(currentWorkspace?.companyID)
      .then((result) => {
        setWebhooks(result?.data?.content);
        setFilteredWebhooks(result?.data?.content);
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      })
      .finally(() => {
        setLoading(false);
      });
  };

  const handleConfirmDelete = () => {
    setDeleteIsLoading(true);

    webhookService
      .remove(
        webhookToDelete.companyID,
        webhookToDelete.repositoryID,
        webhookToDelete.webhookID
      )
      .then(() => {
        showSuccessFlash(t('WEBHOOK_SCREEN.SUCCESS_DELETE'));
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      })
      .finally(() => {
        setDeleteIsLoading(false);
        fetchData();
        setWebhookToDelete(null);
      });
  };

  const onSearchWebhook = (search: string) => {
    if (search) {
      const filtered = webhooks.filter((webhook) =>
        webhook?.url.toLocaleLowerCase().includes(search.toLocaleLowerCase())
      );

      setFilteredWebhooks(filtered);
    } else {
      setFilteredWebhooks(webhooks);
    }
  };

  useEffect(() => {
    fetchData();
    // eslint-disable-next-line
  }, [])

  return (
    <Styled.Wrapper>
      <Styled.Options>
        <SearchBar
          placeholder={t('WEBHOOK_SCREEN.SEARCH')}
          onSearch={(value) => onSearchWebhook(value)}
        />

        <Button
          text={t('WEBHOOK_SCREEN.ADD')}
          rounded
          width={200}
          icon="plus"
          onClick={() => setAddWebhookVisible(true)}
        />
      </Styled.Options>

      <Styled.Content>
        <Styled.TitleWrapper>
          <Styled.Title>{t('WEBHOOK_SCREEN.TITLE')}</Styled.Title>
        </Styled.TitleWrapper>

        <Datatable
          columns={[
            {
              label: t('WEBHOOK_SCREEN.TABLE.METHOD'),
              property: 'method',
              type: 'custom',
              cssClass: ['flex-center'],
            },
            {
              label: t('WEBHOOK_SCREEN.TABLE.URL'),
              property: 'url',
              type: 'text',
            },
            {
              label: t('WEBHOOK_SCREEN.TABLE.DESCRIPTION'),
              property: 'description',
              type: 'text',
            },
            {
              label: t('WEBHOOK_SCREEN.TABLE.REPOSITORY'),
              property: 'repository',
              type: 'text',
            },
            {
              label: t('WEBHOOK_SCREEN.TABLE.ACTION'),
              property: 'actions',
              type: 'actions',
            },
          ]}
          datasource={filteredWebhooks.map((row) => {
            const data: Datasource = {
              ...row,
              id: row.webhookID,
              repository: row?.repository?.name,
              method: (
                <Styled.Tag
                  color={get(
                    colors.methods,
                    row?.method?.toLowerCase(),
                    colors.methods.unknown
                  )}
                >
                  {row.method}
                </Styled.Tag>
              ),
              actions: [
                {
                  title: t('WEBHOOK_SCREEN.TABLE.DELETE'),
                  icon: 'delete',
                  function: () => setWebhookToDelete(row),
                },
                {
                  title: t('WEBHOOK_SCREEN.TABLE.EDIT'),
                  icon: 'edit',
                  function: () => setWebhookToEdit(row),
                },
                {
                  title: t('WEBHOOK_SCREEN.TABLE.COPY'),
                  icon: 'copy',
                  function: () => {
                    setWebhookToCopy(row);
                    setAddWebhookVisible(true);
                  },
                },
              ],
            };
            return data;
          })}
          isLoading={isLoading}
        />
      </Styled.Content>

      <AddWebhook
        isVisible={addWebhookVisible}
        onCancel={() => {
          setAddWebhookVisible(false);
          setWebhookToCopy(null);
        }}
        webhookToCopy={webhookToCopy}
        onConfirm={() => {
          setAddWebhookVisible(false);
          fetchData();
        }}
      />

      <EditWebhook
        isVisible={!!webhookToEdit}
        onCancel={() => setWebhookToEdit(null)}
        webhookToEdit={webhookToEdit}
        onConfirm={() => {
          setWebhookToEdit(null);
          fetchData();
        }}
      />

      <Dialog
        message={t('WEBHOOK_SCREEN.CONFIRM_DELETE')}
        confirmText={t('WEBHOOK_SCREEN.YES')}
        loadingConfirm={deleteIsLoading}
        defaultButton
        hasCancel
        isVisible={!!webhookToDelete}
        onCancel={() => setWebhookToDelete(null)}
        onConfirm={handleConfirmDelete}
      />
    </Styled.Wrapper>
  );
};

export default Webhooks;
