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
import { SearchBar, Button, Icon, Dialog } from 'components';
import { useTranslation } from 'react-i18next';
import repositoryService from 'services/repository';
import { Repository } from 'helpers/interfaces/Repository';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import {
  getCurrentCompany,
  isAdminOfCompany,
} from 'helpers/localStorage/currentCompany';

import AddRepository from './Add';
import EditRepository from './Edit';
import InviteToRepository from './Invite';
import Tokens from './Tokens';
import useFlashMessage from 'helpers/hooks/useFlashMessage';

const Repositories: React.FC = () => {
  const { t } = useTranslation();
  const { companyID } = getCurrentCompany();
  const { dispatchMessage } = useResponseMessage();
  const { showSuccessFlash } = useFlashMessage();

  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [filteredRepos, setFilteredRepos] = useState<Repository[]>([]);

  const [isLoading, setLoading] = useState(false);
  const [deleteIsLoading, setDeleteLoading] = useState(false);

  const [repoToManagerTokens, setRepoToManagerTokens] = useState<Repository>(
    null
  );
  const [repoTodelete, setRepoToDelete] = useState<Repository>(null);
  const [repoToEdit, setRepoToEdit] = useState<Repository>(null);
  const [repoToInvite, setRepoToInvite] = useState<Repository>(null);

  const [addRepoVisible, setAddRepoVisible] = useState(false);

  const fetchData = () => {
    setLoading(true);
    repositoryService
      .getAll(companyID)
      .then((result) => {
        setRepositories(result?.data?.content);
        setFilteredRepos(result?.data?.content);
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      })
      .finally(() => {
        setLoading(false);
      });
  };

  const onSearchRepository = (search: string) => {
    if (search) {
      const filtered = repositories.filter((repo) =>
        repo.name.toLocaleLowerCase().includes(search.toLocaleLowerCase())
      );

      setFilteredRepos(filtered);
    } else {
      setFilteredRepos(repositories);
    }
  };

  const handleConfirmDeleteRepo = () => {
    setDeleteLoading(true);
    repositoryService
      .remove(repoTodelete.companyID, repoTodelete.repositoryID)
      .then(() => {
        showSuccessFlash(t('REPOSITORIES_SCREEN.REMOVE_SUCCESS_REPO'));
        setRepoToDelete(null);
        fetchData();
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      })
      .finally(() => {
        setDeleteLoading(false);
      });
  };

  // eslint-disable-next-line
  useEffect(() => fetchData(), []);

  return (
    <Styled.Wrapper>
      <Styled.Options>
        <SearchBar
          placeholder={t('REPOSITORIES_SCREEN.SEARCH_REPO')}
          onSearch={(value) => onSearchRepository(value)}
        />

        {isAdminOfCompany() ? (
          <Button
            text={t('REPOSITORIES_SCREEN.CREATE_REPO')}
            rounded
            width={180}
            icon="plus"
            onClick={() => setAddRepoVisible(true)}
          />
        ) : null}
      </Styled.Options>

      <Styled.Content>
        <Styled.LoadingWrapper isLoading={isLoading}>
          <Icon name="loading" size="200px" className="loading" />
        </Styled.LoadingWrapper>

        <Styled.Title>{t('REPOSITORIES_SCREEN.TITLE')}</Styled.Title>

        <Styled.Table>
          <Styled.Head>
            <Styled.Column>{t('REPOSITORIES_SCREEN.NAME')}</Styled.Column>
            <Styled.Column>
              {t('REPOSITORIES_SCREEN.DESCRIPTION')}
            </Styled.Column>
            <Styled.Column>{t('REPOSITORIES_SCREEN.ACTION')}</Styled.Column>
          </Styled.Head>

          <Styled.Body>
            {!filteredRepos || filteredRepos.length <= 0 ? (
              <Styled.EmptyText>
                {t('REPOSITORIES_SCREEN.NO_REPOSITORIES')}
              </Styled.EmptyText>
            ) : null}

            {filteredRepos.map((repo) => (
              <Styled.Row key={repo.repositoryID}>
                <Styled.Cell>{repo.name}</Styled.Cell>

                <Styled.Cell>{repo.description || '-'}</Styled.Cell>

                {repo.role === 'admin' ? (
                  <Styled.Cell className="row">
                    <Button
                      outline
                      rounded
                      opaque
                      text={t('REPOSITORIES_SCREEN.EDIT')}
                      width={90}
                      height={30}
                      icon="edit"
                      onClick={() => setRepoToEdit(repo)}
                    />

                    {isAdminOfCompany() ? (
                      <>
                        <Button
                          rounded
                          outline
                          opaque
                          text={t('REPOSITORIES_SCREEN.DELETE')}
                          width={90}
                          height={30}
                          icon="delete"
                          onClick={() => setRepoToDelete(repo)}
                        />

                        <Button
                          outline
                          rounded
                          opaque
                          text={t('REPOSITORIES_SCREEN.INVITE')}
                          width={90}
                          height={30}
                          icon="users"
                          onClick={() => setRepoToInvite(repo)}
                        />
                      </>
                    ) : null}

                    <Button
                      outline
                      rounded
                      opaque
                      text={t('REPOSITORIES_SCREEN.TOKENS')}
                      width={90}
                      height={30}
                      icon="lock"
                      onClick={() => setRepoToManagerTokens(repo)}
                    />
                  </Styled.Cell>
                ) : null}
              </Styled.Row>
            ))}
          </Styled.Body>
        </Styled.Table>
      </Styled.Content>

      <Dialog
        message={t('REPOSITORIES_SCREEN.CONFIRM_DELETE_REPO')}
        confirmText={t('REPOSITORIES_SCREEN.YES')}
        loadingConfirm={deleteIsLoading}
        defaultButton
        hasCancel
        isVisible={!!repoTodelete}
        onCancel={() => setRepoToDelete(null)}
        onConfirm={handleConfirmDeleteRepo}
      />

      <AddRepository
        isVisible={addRepoVisible}
        onCancel={() => setAddRepoVisible(false)}
        onConfirm={() => {
          setAddRepoVisible(false);
          fetchData();
        }}
      />

      <EditRepository
        isVisible={!!repoToEdit}
        onCancel={() => setRepoToEdit(null)}
        repoToEdit={repoToEdit}
        onConfirm={() => {
          setRepoToEdit(null);
          fetchData();
        }}
      />

      <InviteToRepository
        isVisible={!!repoToInvite}
        repoToInvite={repoToInvite}
        onClose={() => setRepoToInvite(null)}
      />

      <Tokens
        isVisible={!!repoToManagerTokens}
        repoToManagerTokens={repoToManagerTokens}
        onClose={() => setRepoToManagerTokens(null)}
      />
    </Styled.Wrapper>
  );
};

export default Repositories;
