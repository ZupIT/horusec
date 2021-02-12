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
import { Button, SearchBar, Dialog, Datatable, Datasource } from 'components';
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

        <Datatable
          columns={[
            {
              label: t('WORKSPACES_SCREEN.USERS.TABLE.USER'),
              property: 'username',
              type: 'text',
            },
            {
              label: t('WORKSPACES_SCREEN.USERS.TABLE.EMAIL'),
              property: 'email',
              type: 'text',
            },
            {
              label: t('WORKSPACES_SCREEN.USERS.TABLE.PERMISSION'),
              property: 'permission',
              type: 'text',
            },
            {
              label: t('WORKSPACES_SCREEN.USERS.TABLE.ACTION'),
              property: 'actions',
              type: 'text',
            },
          ]}
          datasource={filteredUsers.map((row) => {
            const data: Datasource = {
              ...row,
              id: row.accountID,

              permission: t(
                `WORKSPACES_SCREEN.USERS.TABLE.ROLE.${row.role.toLocaleUpperCase()}`
              ),
              actions: [],
            };

            if (row.email !== currentUser?.email) {
              data.actions = [
                {
                  title: t('WORKSPACES_SCREEN.USERS.TABLE.DELETE'),
                  icon: 'delete',
                  function: () => setUserToDelete(row),
                },
                {
                  title: t('WORKSPACES_SCREEN.USERS.TABLE.EDIT'),
                  icon: 'edit',
                  function: () => setUserToEdit(row),
                },
              ];
            }
            return data;
          })}
          isLoading={isLoading}
          emptyListText={t('WORKSPACES_SCREEN.USERS.TABLE.EMPTY')}
        />
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
