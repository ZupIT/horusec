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
import Styled from './styled';
import { useTranslation } from 'react-i18next';
import { Button, Icon, Dialog } from 'components';
import companyService from 'services/company';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { RepositoryToken } from 'helpers/interfaces/RepositoryToken';
import AddToken from './Add';
import { Company } from 'helpers/interfaces/Company';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import { formatToHumanDate } from 'helpers/formatters/date';

interface Props {
  isVisible: boolean;
  selectedCompany: Company;
  onClose: () => void;
}

const Tokens: React.FC<Props> = ({ isVisible, onClose, selectedCompany }) => {
  const { t } = useTranslation();
  const { dispatchMessage } = useResponseMessage();
  const { showSuccessFlash } = useFlashMessage();

  const [tokens, setTokens] = useState<RepositoryToken[]>([]);
  const [isLoading, setLoading] = useState(true);
  const [deleteIsLoading, setDeleteIsLoading] = useState(false);

  const [tokenToDelete, setTokenToDelete] = useState<RepositoryToken>(null);
  const [addTokenVisible, setAddTokenVisible] = useState(false);

  const fetchData = () => {
    setLoading(true);
    companyService
      .getAllTokens(selectedCompany.companyID)
      .then((result) => {
        setTokens(result?.data?.content);
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      })
      .finally(() => {
        setLoading(false);
      });
  };

  const handleConfirmDeleteToken = () => {
    setDeleteIsLoading(true);
    companyService
      .removeToken(tokenToDelete.companyID, tokenToDelete.tokenID)
      .then(() => {
        showSuccessFlash(t('WORKSPACES_SCREEN.REMOVE_SUCCESS_TOKEN'));
        setTokenToDelete(null);
        fetchData();
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      })
      .finally(() => {
        setDeleteIsLoading(false);
      });
  };

  useEffect(() => {
    if (selectedCompany) {
      fetchData();
    }
    //eslint-disable-next-line
  }, [selectedCompany]);

  return isVisible ? (
    <Styled.Background>
      <Styled.Wrapper>
        <Styled.Header>
          <Styled.Title>{t('WORKSPACES_SCREEN.TOKENS')}</Styled.Title>

          <Styled.Close name="close" size="24px" onClick={onClose} />
        </Styled.Header>

        <Button
          text={t('WORKSPACES_SCREEN.ADD_TOKEN')}
          rounded
          width={150}
          icon="plus"
          onClick={() => setAddTokenVisible(true)}
        />

        <Styled.Table>
          <Styled.LoadingWrapper isLoading={isLoading}>
            <Icon name="loading" size="120px" className="loading" />
          </Styled.LoadingWrapper>

          <Styled.Head>
            <Styled.Column>{t('WORKSPACES_SCREEN.TOKEN')}</Styled.Column>
            <Styled.Column>{t('WORKSPACES_SCREEN.DESCRIPTION')}</Styled.Column>
            <Styled.Column>{t('WORKSPACES_SCREEN.EXPIRES')}</Styled.Column>
            <Styled.Column>{t('WORKSPACES_SCREEN.ACTION')}</Styled.Column>
          </Styled.Head>

          <Styled.Body>
            {!tokens || tokens.length <= 0 ? (
              <Styled.EmptyText>
                {t('WORKSPACES_SCREEN.NO_TOKENS')}
              </Styled.EmptyText>
            ) : null}

            {tokens.map((token) => (
              <Styled.Row key={token.tokenID}>
                <Styled.Cell>***************{token.suffixValue}</Styled.Cell>

                <Styled.Cell>{token.description}</Styled.Cell>

                <Styled.Cell>{formatToHumanDate(token.expiresAt)}</Styled.Cell>

                <Styled.Cell className="row">
                  <Button
                    rounded
                    outline
                    opaque
                    text={t('WORKSPACES_SCREEN.DELETE')}
                    width={90}
                    height={30}
                    icon="delete"
                    onClick={() => setTokenToDelete(token)}
                  />
                </Styled.Cell>
              </Styled.Row>
            ))}
          </Styled.Body>
        </Styled.Table>
      </Styled.Wrapper>

      <Dialog
        message={t('WORKSPACES_SCREEN.CONFIRM_DELETE_TOKEN')}
        confirmText={t('WORKSPACES_SCREEN.YES')}
        loadingConfirm={deleteIsLoading}
        defaultButton
        hasCancel
        isVisible={!!tokenToDelete}
        onCancel={() => setTokenToDelete(null)}
        onConfirm={handleConfirmDeleteToken}
      />

      <AddToken
        isVisible={addTokenVisible}
        selectedCompany={selectedCompany}
        onCancel={() => setAddTokenVisible(false)}
        onConfirm={() => {
          setAddTokenVisible(false);
          fetchData();
        }}
      />
    </Styled.Background>
  ) : null;
};

export default Tokens;
