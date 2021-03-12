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
import Styled from './styled';
import { SearchBar, Button, Dialog, Datatable, Datasource } from 'components';
import { useTranslation } from 'react-i18next';
import useWorkspace from 'helpers/hooks/useWorkspace';
import { Workspace } from 'helpers/interfaces/Workspace';
import { roles } from 'helpers/enums/roles';
import { formatToHumanDate } from 'helpers/formatters/date';
import companyService from 'services/company';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { getCurrentConfig } from 'helpers/localStorage/horusecConfig';
import { authTypes } from 'helpers/enums/authTypes';

import HandleWorkspace from './Handle';
import Tokens from './Tokens';
import Users from './Users';

const Workspaces: React.FC = () => {
  const { t } = useTranslation();
  const { dispatchMessage } = useResponseMessage();
  const { showSuccessFlash } = useFlashMessage();
  const { allWorkspaces, fetchAllWorkspaces } = useWorkspace();
  const { authType } = getCurrentConfig();

  const [deleteIsLoading, setDeleteIsLoading] = useState(false);
  const [workspaceToDelete, setWorkspaceToDelete] = useState<Workspace>(null);
  const [workspaceToEdit, setWorkspaceToEdit] = useState<Workspace>(null);
  const [handleWorkspaceVisible, setHandleWorkspaceVisible] = useState(false);
  const [
    workspaceToManagerTokens,
    setWorkspaceToManagerTokens,
  ] = useState<Workspace>(null);
  const [
    workspaceToManagerUsers,
    setWorkspaceToManagerUsers,
  ] = useState<Workspace>(null);
  const [filteredWorkspaces, setFilteredWorkspaces] = useState<Workspace[]>(
    allWorkspaces
  );

  const onSearch = (search: string) => {
    if (search) {
      const filtered = allWorkspaces.filter((workspace) =>
        workspace.name.toLocaleLowerCase().includes(search.toLocaleLowerCase())
      );

      setFilteredWorkspaces(filtered);
    } else {
      setFilteredWorkspaces(allWorkspaces);
    }
  };

  const handleConfirmDeleteWorkspace = () => {
    setDeleteIsLoading(true);
    companyService
      .remove(workspaceToDelete.companyID)
      .then(() => {
        showSuccessFlash(t('WORKSPACES_SCREEN.REMOVE_SUCCESS'));
        setWorkspaceToDelete(null);
        fetchAllWorkspaces();
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      })
      .finally(() => {
        setDeleteIsLoading(false);
      });
  };

  const setVisibleHandleModal = (isVisible: boolean, workspace?: Workspace) => {
    setHandleWorkspaceVisible(isVisible);
    setWorkspaceToEdit(workspace || null);
  };

  useEffect(() => {
    setFilteredWorkspaces(allWorkspaces);
  }, [allWorkspaces]);

  return (
    <Styled.Wrapper>
      <Styled.Options>
        <SearchBar
          placeholder={t('WORKSPACES_SCREEN.SEARCH')}
          onSearch={(value) => onSearch(value)}
        />

        <Button
          text={t('WORKSPACES_SCREEN.ADD')}
          rounded
          width={180}
          icon="plus"
          onClick={() => setVisibleHandleModal(true)}
        />
      </Styled.Options>

      <Styled.Content>
        <Styled.Title>{t('WORKSPACES_SCREEN.TITLE')}</Styled.Title>

        <Datatable
          columns={[
            {
              label: t('WORKSPACES_SCREEN.TABLE.NAME'),
              property: 'name',
              type: 'text',
            },
            {
              label: t('WORKSPACES_SCREEN.TABLE.DATE'),
              property: 'date',
              type: 'text',
            },
            {
              label: t('WORKSPACES_SCREEN.TABLE.DESCRIPTION'),
              property: 'description',
              type: 'text',
            },
            {
              label: t('WORKSPACES_SCREEN.TABLE.ACTION'),
              property: 'actions',
              type: 'actions',
            },
          ]}
          datasource={filteredWorkspaces.map((row) => {
            const data: Datasource = {
              ...row,
              id: row.companyID,
              date: formatToHumanDate(row.createdAt),
              actions: [],
            };

            if (row.role === roles.ADMIN) {
              data.actions.push({
                title: t('WORKSPACES_SCREEN.TABLE.EDIT'),
                icon: 'edit',
                function: () => setVisibleHandleModal(true, row),
              });

              data.actions.push({
                title: t('WORKSPACES_SCREEN.TABLE.REMOVE'),
                icon: 'delete',
                function: () => setWorkspaceToDelete(row),
              });

              if (authType !== authTypes.LDAP) {
                data.actions.push({
                  title: t('WORKSPACES_SCREEN.TABLE.USERS'),
                  icon: 'grid',
                  function: () => setWorkspaceToManagerUsers(row),
                });
              }

              data.actions.push({
                title: t('WORKSPACES_SCREEN.TABLE.TOKENS'),
                icon: 'lock',
                function: () => setWorkspaceToManagerTokens(row),
              });
            }
            return data;
          })}
          emptyListText={t('REPOSITORIES_SCREEN.NO_REPOSITORIES')}
          fixed={false}
        />
      </Styled.Content>

      <HandleWorkspace
        isVisible={handleWorkspaceVisible}
        workspaceToEdit={workspaceToEdit}
        onConfirm={() => {
          setVisibleHandleModal(false);
          fetchAllWorkspaces();
        }}
        onCancel={() => setVisibleHandleModal(false)}
      />

      <Dialog
        message={t('WORKSPACES_SCREEN.CONFIRM_DELETE')}
        confirmText={t('WORKSPACES_SCREEN.YES')}
        loadingConfirm={deleteIsLoading}
        defaultButton
        hasCancel
        isVisible={!!workspaceToDelete}
        onCancel={() => setWorkspaceToDelete(null)}
        onConfirm={handleConfirmDeleteWorkspace}
      />

      <Tokens
        isVisible={!!workspaceToManagerTokens}
        selectedWorkspace={workspaceToManagerTokens}
        onClose={() => setWorkspaceToManagerTokens(null)}
      />

      <Users
        isVisible={!!workspaceToManagerUsers}
        selectedWorkspace={workspaceToManagerUsers}
        onClose={() => setWorkspaceToManagerUsers(null)}
      />
    </Styled.Wrapper>
  );
};

export default Workspaces;
