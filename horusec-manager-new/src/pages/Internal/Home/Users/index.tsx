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
import companyService from 'services/company';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { getCurrentCompany } from 'helpers/localStorage/currentCompany';
import { Account } from 'helpers/interfaces/Account';

import InviteToCompany from './Invite';
import EditUserRole from './Edit';

const Users: React.FC = () => {
  const { t } = useTranslation();
  const { companyID } = getCurrentCompany();
  const { dispatchMessage } = useResponseMessage();

  const [users, setUsers] = useState<Account[]>([]);
  const [filteredUsers, setFilteredUsers] = useState<Account[]>([]);

  const [isLoading, setLoading] = useState(false);
  const [deleteIsLoading, setDeleteLoading] = useState(false);

  const [userToDelete, setUserToDelete] = useState<Account>(null);
  const [userToEdit, setUserToEdit] = useState<Account>(null);

  const [inviteUserVisible, setInviteUserVisible] = useState(false);

  const fetchData = () => {
    setLoading(true);
    companyService
      .getUsersInCompany(companyID)
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

  const onSearchUser = (search: string) => {
    if (search) {
      const filtered = users.filter((user) =>
        user.email.toLocaleLowerCase().includes(search.toLocaleLowerCase())
      );

      setFilteredUsers(filtered);
    } else {
      setFilteredUsers(users);
    }
  };

  const handleConfirmDeleteUser = () => {
    setDeleteLoading(true);
    companyService
      .removeUserInCompany(companyID, userToDelete.accountID)
      .then(() => {
        setUserToDelete(null);
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
          placeholder={t('USERS_SCREEN.SEARCH')}
          onSearch={(value) => onSearchUser(value)}
        />

        <Button
          text={t('USERS_SCREEN.INVITE')}
          rounded
          width={180}
          icon="plus"
          onClick={() => setInviteUserVisible(true)}
        />
      </Styled.Options>

      <Styled.Content>
        <Styled.LoadingWrapper isLoading={isLoading}>
          <Icon name="loading" size="200px" className="loading" />
        </Styled.LoadingWrapper>

        <Styled.Title>{t('USERS_SCREEN.TITLE')}</Styled.Title>

        <Styled.Table>
          <Styled.Head>
            <Styled.Column>{t('USERS_SCREEN.TABLE.USER')}</Styled.Column>
            <Styled.Column>{t('USERS_SCREEN.TABLE.EMAIL')}</Styled.Column>
            <Styled.Column>{t('USERS_SCREEN.TABLE.PERMISSION')}</Styled.Column>
            <Styled.Column>{t('USERS_SCREEN.TABLE.ACTION')}</Styled.Column>
          </Styled.Head>

          <Styled.Body>
            {!filteredUsers || filteredUsers.length <= 0 ? (
              <Styled.EmptyText>
                {t('USERS_SCREEN.TABLE.EMPTY')}
              </Styled.EmptyText>
            ) : null}

            {filteredUsers.map((user) => (
              <Styled.Row key={user.accountID}>
                <Styled.Cell>{user.username}</Styled.Cell>

                <Styled.Cell>{user.email}</Styled.Cell>

                <Styled.Cell>
                  {user.role === 'admin'
                    ? t('USERS_SCREEN.TABLE.ROLE.ADMIN')
                    : t('USERS_SCREEN.TABLE.ROLE.MEMBER')}
                </Styled.Cell>

                <Styled.Cell className="row">
                  <Button
                    rounded
                    outline
                    opaque
                    text={t('USERS_SCREEN.TABLE.DELETE')}
                    width={90}
                    height={30}
                    icon="delete"
                    onClick={() => setUserToDelete(user)}
                  />

                  <Button
                    outline
                    rounded
                    opaque
                    text={t('USERS_SCREEN.TABLE.EDIT')}
                    width={90}
                    height={30}
                    icon="edit"
                    onClick={() => setUserToEdit(user)}
                  />
                </Styled.Cell>
              </Styled.Row>
            ))}
          </Styled.Body>
        </Styled.Table>
      </Styled.Content>

      <Dialog
        message={t('USERS_SCREEN.CONFIRM_DELETE')}
        confirmText={t('USERS_SCREEN.YES')}
        loadingConfirm={deleteIsLoading}
        defaultButton
        hasCancel
        isVisible={!!userToDelete}
        onCancel={() => setUserToDelete(null)}
        onConfirm={handleConfirmDeleteUser}
      />

      <InviteToCompany
        isVisible={inviteUserVisible}
        onCancel={() => setInviteUserVisible(false)}
        onConfirm={() => {
          setInviteUserVisible(false);
          fetchData();
        }}
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
    </Styled.Wrapper>
  );
};

export default Users;
