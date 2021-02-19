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
import { SearchBar, Button, Dialog, Datatable, Datasource } from 'components';
import { useTranslation } from 'react-i18next';
import repositoryService from 'services/repository';
import { Repository } from 'helpers/interfaces/Repository';
import useResponseMessage from 'helpers/hooks/useResponseMessage';

import HandleRepository from './Handle';
import InviteToRepository from './Invite';
import Tokens from './Tokens';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import useWorkspace from 'helpers/hooks/useWorkspace';
import { getCurrentConfig } from 'helpers/localStorage/horusecConfig';
import { authTypes } from 'helpers/enums/authTypes';

const Repositories: React.FC = () => {
  const { t } = useTranslation();
  const { currentWorkspace, isAdminOfWorkspace } = useWorkspace();
  const { dispatchMessage } = useResponseMessage();
  const { showSuccessFlash } = useFlashMessage();
  const { authType } = getCurrentConfig();

  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [filteredRepos, setFilteredRepos] = useState<Repository[]>([]);

  const [isLoading, setLoading] = useState(false);
  const [handleRepositoryVisible, sethandleRepositoryVisible] = useState(false);
  const [deleteIsLoading, setDeleteLoading] = useState(false);

  const [repoToManagerTokens, setRepoToManagerTokens] = useState<Repository>(
    null
  );
  const [repoTodelete, setRepoToDelete] = useState<Repository>(null);
  const [repoToEdit, setRepoToEdit] = useState<Repository>(null);
  const [repoToInvite, setRepoToInvite] = useState<Repository>(null);

  const fetchData = () => {
    setLoading(true);
    repositoryService
      .getAll(currentWorkspace?.companyID)
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

  const setVisibleHandleModal = (
    isVisible: boolean,
    repository?: Repository
  ) => {
    sethandleRepositoryVisible(isVisible);
    setRepoToEdit(repository || null);
  };

  // eslint-disable-next-line
  useEffect(() => fetchData(), [currentWorkspace]);

  return (
    <Styled.Wrapper>
      <Styled.Options>
        <SearchBar
          placeholder={t('REPOSITORIES_SCREEN.SEARCH_REPO')}
          onSearch={(value) => onSearchRepository(value)}
        />

        {isAdminOfWorkspace ? (
          <Button
            text={t('REPOSITORIES_SCREEN.CREATE_REPO')}
            rounded
            width={180}
            icon="plus"
            onClick={() => setVisibleHandleModal(true)}
          />
        ) : null}
      </Styled.Options>

      <Styled.Content>
        <Styled.Title>{t('REPOSITORIES_SCREEN.TITLE')}</Styled.Title>

        <Datatable
          columns={[
            {
              label: t('REPOSITORIES_SCREEN.NAME'),
              property: 'name',
              type: 'text',
            },
            {
              label: t('REPOSITORIES_SCREEN.DESCRIPTION'),
              property: 'description',
              type: 'text',
            },
            {
              label: t('REPOSITORIES_SCREEN.ACTION'),
              property: 'actions',
              type: 'actions',
            },
          ]}
          datasource={filteredRepos.map((row) => {
            const repo: Datasource = {
              ...row,
              id: row.repositoryID,
              actions: [],
            };

            if (row.role === 'admin') {
              repo.actions.push({
                title: t('REPOSITORIES_SCREEN.EDIT'),
                icon: 'edit',
                function: () => setVisibleHandleModal(true, row),
              });

              if (isAdminOfWorkspace) {
                repo.actions.push({
                  title: t('REPOSITORIES_SCREEN.DELETE'),
                  icon: 'delete',
                  function: () => setRepoToDelete(row),
                });

                if (authType !== authTypes.LDAP) {
                  repo.actions.push({
                    title: t('REPOSITORIES_SCREEN.INVITE'),
                    icon: 'users',
                    function: () => setRepoToInvite(row),
                  });
                }
              }

              repo.actions.push({
                title: t('REPOSITORIES_SCREEN.TOKENS'),
                icon: 'lock',
                function: () => setRepoToManagerTokens(row),
              });
            }
            return repo;
          })}
          isLoading={isLoading}
          emptyListText={t('REPOSITORIES_SCREEN.NO_REPOSITORIES')}
        />
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

      <HandleRepository
        isVisible={handleRepositoryVisible}
        repositoryToEdit={repoToEdit}
        onConfirm={() => {
          setVisibleHandleModal(false);
          fetchData();
        }}
        onCancel={() => setVisibleHandleModal(false)}
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
