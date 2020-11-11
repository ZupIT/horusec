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
import { useTranslation } from 'react-i18next';
import Styled from './styled';
import { Button, Icon } from 'components';
import { Webhook } from 'helpers/interfaces/Webhook';
import { useTheme } from 'styled-components';
import { get } from 'lodash';

import AddWebhook from './Add';

const mockOfWebhooks: Webhook[] = [
  {
    url: 'https://rankeer.app/hook/horusec',
    method: 'post',
    description: 'Hook para report das vulnerabilidades do meu serviço de api.',
    repository: {
      name: 'Beagle',
      companyID: '123',
      description: 'Teste',
    },
    companyID: '123',
  },
  {
    url: 'https://api.charlescd.io/security/report',
    method: 'post',
    description: 'Endpoint para receber detalhes das analises',
    repository: {
      name: 'Charles CD',
      companyID: '123',
      description: 'Teste',
    },
    companyID: '123',
  },
  {
    url: 'https://app.myservice.com/webhook-horusec',
    method: 'get',
    description: 'URL para callback das analises do horusec.',
    repository: {
      name: 'Ritch',
      companyID: '123',
      description: 'Teste',
    },
    companyID: '123',
  },
];

const Webhooks: React.FC = () => {
  const { t } = useTranslation();
  const { colors } = useTheme();

  const [webhooks, setWebhooks] = useState<Webhook[]>(mockOfWebhooks);
  const [isLoading, setLoading] = useState(false);
  const [addWebhookVisible, setAddWebhookVisible] = useState(false);

  return (
    <Styled.Wrapper>
      <Styled.Content>
        <Styled.TitleWrapper>
          <Styled.Title>{t('WEBHOOK_SCREEN.TITLE')}</Styled.Title>

          <Button
            text={t('WEBHOOK_SCREEN.ADD')}
            rounded
            width={150}
            icon="plus"
            onClick={() => setAddWebhookVisible(true)}
          />
        </Styled.TitleWrapper>

        <Styled.Table>
          <Styled.LoadingWrapper isLoading={isLoading}>
            <Icon name="loading" size="200px" className="loading" />
          </Styled.LoadingWrapper>

          <Styled.Head>
            <Styled.Column>{t('WEBHOOK_SCREEN.TABLE.METHOD')}</Styled.Column>

            <Styled.Column>{t('WEBHOOK_SCREEN.TABLE.URL')}</Styled.Column>

            <Styled.Column>
              {t('WEBHOOK_SCREEN.TABLE.REPOSITORY')}
            </Styled.Column>

            <Styled.Column>
              {t('WEBHOOK_SCREEN.TABLE.DESCRIPTION')}
            </Styled.Column>

            <Styled.Column>{t('WEBHOOK_SCREEN.TABLE.ACTION')}</Styled.Column>
          </Styled.Head>

          <Styled.Body>
            {!webhooks || webhooks.length <= 0 ? (
              <Styled.EmptyText>
                {t('WEBHOOK_SCREEN.TABLE.EMPTY')}
              </Styled.EmptyText>
            ) : null}

            {webhooks.map((webhook, index) => (
              <Styled.Row key={index}>
                <Styled.Cell className="flex-center">
                  <Styled.Tag
                    color={get(
                      colors.methods,
                      webhook.method,
                      colors.methods.unknown
                    )}
                  >
                    {webhook.method}
                  </Styled.Tag>
                </Styled.Cell>

                <Styled.Cell>{webhook.url}</Styled.Cell>

                <Styled.Cell>{webhook?.repository?.name}</Styled.Cell>

                <Styled.Cell>{webhook.description}</Styled.Cell>

                <Styled.Cell className="row">
                  <Button
                    rounded
                    outline
                    opaque
                    text={t('WEBHOOK_SCREEN.TABLE.DELETE')}
                    width={90}
                    height={30}
                    icon="delete"
                    onClick={() => console.log(webhook)}
                  />

                  <Button
                    outline
                    rounded
                    opaque
                    text={t('WEBHOOK_SCREEN.TABLE.EDIT')}
                    width={90}
                    height={30}
                    icon="edit"
                    onClick={() => console.log(webhook)}
                  />
                </Styled.Cell>
              </Styled.Row>
            ))}
          </Styled.Body>
        </Styled.Table>
      </Styled.Content>

      <AddWebhook
        isVisible={addWebhookVisible}
        onCancel={() => setAddWebhookVisible(false)}
        onConfirm={() => setAddWebhookVisible(false)}
      />
    </Styled.Wrapper>
  );
};

export default Webhooks;
