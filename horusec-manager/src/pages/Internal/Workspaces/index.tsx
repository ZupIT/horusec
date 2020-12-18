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
import { SearchBar, Button, Dialog } from 'components';
import { useTranslation } from 'react-i18next';
import useWorkspace from 'helpers/hooks/useWorkspace';
import { Workspace } from 'helpers/interfaces/Workspace';
import { roles } from 'helpers/enums/roles';
import { formatToHumanDate } from 'helpers/formatters/date';
import companyService from 'services/company';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import useResponseMessage from 'helpers/hooks/useResponseMessage';

import AddWorkspace from './Add';

const Workspaces: React.FC = () => {
  const { t } = useTranslation();
  const { dispatchMessage } = useResponseMessage();
  const { showSuccessFlash } = useFlashMessage();
  const { allWorkspaces, fetchAllWorkspaces } = useWorkspace();

  const [deleteIsLoading, setDeleteIsLoading] = useState(false);
  const [workspaceToDelete, setWorkspaceToDelete] = useState<Workspace>(null);
  const [addWorkspaceVisible, setAddWorkspaceVisible] = useState(false);
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
          onClick={() => setAddWorkspaceVisible(true)}
        />
      </Styled.Options>

      <Styled.Content>
        <Styled.Title>{t('WORKSPACES_SCREEN.TITLE')}</Styled.Title>

        <Styled.Table>
          <Styled.Head>
            <Styled.Column>{t('WORKSPACES_SCREEN.TABLE.NAME')}</Styled.Column>
            <Styled.Column>{t('WORKSPACES_SCREEN.TABLE.DATE')}</Styled.Column>
            <Styled.Column>
              {t('WORKSPACES_SCREEN.TABLE.DESCRIPTION')}
            </Styled.Column>
            <Styled.Column>{t('WORKSPACES_SCREEN.TABLE.ACTION')}</Styled.Column>
          </Styled.Head>

          <Styled.Body>
            {filteredWorkspaces.map((workspace) => (
              <Styled.Row key={workspace.companyID}>
                <Styled.Cell>{workspace.name}</Styled.Cell>

                <Styled.Cell>
                  {formatToHumanDate(workspace.createdAt)}
                </Styled.Cell>

                <Styled.Cell>{workspace.description || '-'}</Styled.Cell>

                <Styled.Cell className="row">
                  {workspace.role === roles.ADMIN ? (
                    <>
                      <Button
                        outline
                        rounded
                        opaque
                        text={t('WORKSPACES_SCREEN.TABLE.EDIT')}
                        width={100}
                        height={30}
                        icon="edit"
                        onClick={() => console.log(workspace)}
                      />

                      <Button
                        rounded
                        outline
                        opaque
                        text={t('WORKSPACES_SCREEN.TABLE.REMOVE')}
                        width={100}
                        height={30}
                        icon="delete"
                        onClick={() => setWorkspaceToDelete(workspace)}
                      />

                      <Button
                        outline
                        rounded
                        opaque
                        text={t('WORKSPACES_SCREEN.TABLE.USERS')}
                        width={200}
                        height={30}
                        icon="grid"
                        onClick={() => console.log(workspace)}
                      />

                      <Button
                        outline
                        rounded
                        opaque
                        text={t('WORKSPACES_SCREEN.TABLE.TOKENS')}
                        width={100}
                        height={30}
                        icon="lock"
                        onClick={() => console.log(workspace)}
                      />
                    </>
                  ) : null}
                </Styled.Cell>
              </Styled.Row>
            ))}
          </Styled.Body>
        </Styled.Table>
      </Styled.Content>

      <AddWorkspace
        isVisible={addWorkspaceVisible}
        onConfirm={() => {
          setAddWorkspaceVisible(false);
          fetchAllWorkspaces();
        }}
        onCancel={() => setAddWorkspaceVisible(false)}
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
    </Styled.Wrapper>
  );
};

export default Workspaces;
