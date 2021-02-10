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
import { Repository } from 'helpers/interfaces/Repository';
import { useTranslation } from 'react-i18next';
import { Button, Dialog, Datatable, Datasource } from 'components';
import repositoryService from 'services/repository';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { RepositoryToken } from 'helpers/interfaces/RepositoryToken';
import AddToken from './Add';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import { formatToHumanDate } from 'helpers/formatters/date';

interface Props {
  isVisible: boolean;
  repoToManagerTokens: Repository;
  onClose: () => void;
}

const Tokens: React.FC<Props> = ({
  isVisible,
  onClose,
  repoToManagerTokens,
}) => {
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
    repositoryService
      .getAllTokens(
        repoToManagerTokens.companyID,
        repoToManagerTokens.repositoryID
      )
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
    repositoryService
      .removeToken(
        tokenToDelete.companyID,
        tokenToDelete.repositoryID,
        tokenToDelete.tokenID
      )
      .then(() => {
        showSuccessFlash(t('REPOSITORIES_SCREEN.REMOVE_SUCCESS_TOKEN'));
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
    if (repoToManagerTokens) {
      fetchData();
    }
    //eslint-disable-next-line
  }, [repoToManagerTokens]);

  return isVisible ? (
    <Styled.Background>
      <Styled.Wrapper>
        <Styled.Header>
          <Styled.Title>{t('REPOSITORIES_SCREEN.TOKENS')}</Styled.Title>

          <Styled.Close name="close" size="24px" onClick={onClose} />
        </Styled.Header>

        <Button
          text={t('REPOSITORIES_SCREEN.ADD_TOKEN')}
          rounded
          width={150}
          icon="plus"
          onClick={() => setAddTokenVisible(true)}
        />

        <Datatable
          columns={[
            { label: t('REPOSITORIES_SCREEN.TOKEN'), property: 'token', type: 'text' },
            { label: t('REPOSITORIES_SCREEN.DESCRIPTION'), property: 'description', type: 'text' },
            { label: t('REPOSITORIES_SCREEN.EXPIRES'), property: 'expiresAt', type: 'text' },
            { label: t('REPOSITORIES_SCREEN.ACTION'), property: 'actions', type: 'actions' },
          ]}
          datasource={tokens.map(row => {
            let repo: Datasource = {
              ...row,
              id: row.tokenID,
              token: '***************' + row.suffixValue,
              expiresAt: formatToHumanDate(row.expiresAt),
              actions: [
                { title: t('REPOSITORIES_SCREEN.DELETE'), icon: 'delete', function: () => setTokenToDelete(row) }
              ]
            };
            return repo;
          })}
          isLoading={isLoading}
          emptyListText={t('REPOSITORIES_SCREEN.NO_TOKENS')}
        />

      </Styled.Wrapper>

      <Dialog
        message={t('REPOSITORIES_SCREEN.CONFIRM_DELETE_TOKEN')}
        confirmText={t('REPOSITORIES_SCREEN.YES')}
        loadingConfirm={deleteIsLoading}
        defaultButton
        hasCancel
        isVisible={!!tokenToDelete}
        onCancel={() => setTokenToDelete(null)}
        onConfirm={handleConfirmDeleteToken}
      />

      <AddToken
        isVisible={addTokenVisible}
        currentRepository={repoToManagerTokens}
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
