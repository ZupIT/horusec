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
import { Button, SearchBar, Dialog, Icon } from 'components';
import { useTranslation } from 'react-i18next';
import Styled from './styled';
import companyService from 'services/company';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import { Workspace } from 'helpers/interfaces/Workspace';
import { Account } from 'helpers/interfaces/Account';
import { getCurrentUser } from 'helpers/localStorage/currentUser';

import InviteToCompany from './Invite';
import EditUserRole from './Edit';

interface Props {
  isVisible: boolean;
  selectedWorkspace: Workspace;
  onClose: () => void;
}

const Users: React.FC<Props> = ({ isVisible, onClose, selectedWorkspace }) => {
  const { t } = useTranslation();
  const currentUser = getCurrentUser();
  const { dispatchMessage } = useResponseMessage();
  const { showSuccessFlash } = useFlashMessage();

  const [isLoading, setLoading] = useState(false);
  const [deleteIsLoading, setDeleteIsLoading] = useState(false);

  const [users, setUsers] = useState<Account[]>([]);
  const [filteredUsers, setFilteredUsers] = useState<Account[]>([]);

  const [userToEdit, setUserToEdit] = useState<Account>(null);
  const [userToDelete, setUserToDelete] = useState<Account>(null);
  const [inviteUserVisible, setInviteUserVisible] = useState(false);

  const onSearch = (search: string) => {
    if (search) {
      const filtered = users.filter((user) =>
        user.email.toLocaleLowerCase().includes(search.toLocaleLowerCase())
      );

      setFilteredUsers(filtered);
    } else {
      setFilteredUsers(users);
    }
  };

  const fetchData = () => {
    setLoading(true);
    companyService
      .getUsersInCompany(selectedWorkspace?.companyID)
      .then((result) => {
        setUsers(result?.data?.content);
        setFilteredUsers(result?.data?.content);
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      })
      .finally(() => {
        setLoading(false);
      });
  };

  const handleConfirmDeleteUser = () => {
    setDeleteIsLoading(true);
    companyService
      .removeUserInCompany(selectedWorkspace?.companyID, userToDelete.accountID)
      .then(() => {
        showSuccessFlash(t('WORKSPACES_SCREEN.USERS.REMOVE_SUCCESS'));
        setUserToDelete(null);
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
    if (selectedWorkspace) fetchData();

    // eslint-disable-next-line
  }, [selectedWorkspace]);

  return isVisible ? (
    <Styled.Background>
      <Styled.Wrapper>
        <Styled.Header>
          <Styled.Title>{t('WORKSPACES_SCREEN.USERS.TITLE')}</Styled.Title>

          <Styled.Close name="close" size="24px" onClick={onClose} />
        </Styled.Header>

        <Styled.Header>
          <SearchBar
            placeholder={t('WORKSPACES_SCREEN.USERS.SEARCH')}
            onSearch={(value) => onSearch(value)}
          />

          <Button
            text={t('WORKSPACES_SCREEN.USERS.INVITE')}
            rounded
            width={180}
            icon="plus"
            onClick={() => setInviteUserVisible(true)}
          />
        </Styled.Header>

        <Styled.Table>
          <Styled.LoadingWrapper isLoading={isLoading}>
            <Icon name="loading" size="120px" className="loading" />
          </Styled.LoadingWrapper>

          <Styled.Head>
            <Styled.Column>
              {t('WORKSPACES_SCREEN.USERS.TABLE.USER')}
            </Styled.Column>
            <Styled.Column>
              {t('WORKSPACES_SCREEN.USERS.TABLE.EMAIL')}
            </Styled.Column>
            <Styled.Column>
              {t('WORKSPACES_SCREEN.USERS.TABLE.PERMISSION')}
            </Styled.Column>
            <Styled.Column>
              {t('WORKSPACES_SCREEN.USERS.TABLE.ACTION')}
            </Styled.Column>
          </Styled.Head>

          <Styled.Body>
            {!filteredUsers || filteredUsers.length <= 0 ? (
              <Styled.EmptyText>
                {t('WORKSPACES_SCREEN.USERS.TABLE.EMPTY')}
              </Styled.EmptyText>
            ) : null}

            {filteredUsers.map((user) => (
              <Styled.Row key={user.accountID}>
                <Styled.Cell>{user.username}</Styled.Cell>

                <Styled.Cell>{user.email}</Styled.Cell>

                <Styled.Cell>
                  {t(
                    `WORKSPACES_SCREEN.USERS.TABLE.ROLE.${user.role.toLocaleUpperCase()}`
                  )}
                </Styled.Cell>

                <Styled.Cell className="row">
                  {user.email !== currentUser?.email ? (
                    <>
                      <Button
                        rounded
                        outline
                        opaque
                        text={t('WORKSPACES_SCREEN.USERS.TABLE.DELETE')}
                        width={90}
                        height={30}
                        icon="delete"
                        onClick={() => setUserToDelete(user)}
                      />

                      <Button
                        outline
                        rounded
                        opaque
                        text={t('WORKSPACES_SCREEN.USERS.TABLE.EDIT')}
                        width={90}
                        height={30}
                        icon="edit"
                        onClick={() => setUserToEdit(user)}
                      />
                    </>
                  ) : null}
                </Styled.Cell>
              </Styled.Row>
            ))}
          </Styled.Body>
        </Styled.Table>
      </Styled.Wrapper>

      <InviteToCompany
        isVisible={inviteUserVisible}
        selectedWorkspace={selectedWorkspace}
        onCancel={() => setInviteUserVisible(false)}
        onConfirm={() => {
          setInviteUserVisible(false);
          fetchData();
        }}
      />

      <Dialog
        message={t('WORKSPACES_SCREEN.USERS.CONFIRM_DELETE')}
        confirmText={t('WORKSPACES_SCREEN.USERS.YES')}
        loadingConfirm={deleteIsLoading}
        defaultButton
        hasCancel
        isVisible={!!userToDelete}
        onCancel={() => setUserToDelete(null)}
        onConfirm={handleConfirmDeleteUser}
      />

      <EditUserRole
        isVisible={!!userToEdit}
        onCancel={() => setUserToEdit(null)}
        userToEdit={userToEdit}
        onConfirm={() => {
          setUserToEdit(null);
          fetchData();
        }}
      />
    </Styled.Background>
  ) : null;
};

export default Users;
