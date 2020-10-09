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
import { Repository } from 'helpers/interfaces/Repository';
import { SearchBar, Checkbox, Select, Icon, Permissions } from 'components';
import { Account } from 'helpers/interfaces/Account';
import repositoryService from 'services/repository';
import companyService from 'services/company';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { getCurrentUser } from 'helpers/localStorage/currentUser';
import { findIndex, cloneDeep } from 'lodash';
import useFlashMessage from 'helpers/hooks/useFlashMessage';

interface Props {
  isVisible?: boolean;
  repoToInvite: Repository;
  onClose: () => void;
}

const InviteToRepository: React.FC<Props> = ({
  isVisible,
  repoToInvite,
  onClose,
}) => {
  const { t } = useTranslation();
  const { dispatchMessage } = useResponseMessage();
  const { showSuccessFlash } = useFlashMessage();
  const currentUser = getCurrentUser();

  const [userAccounts, setUserAccounts] = useState<Account[]>([]);
  const [filteredUserAccounts, setFilteredUserAccounts] = useState<Account[]>(
    []
  );
  const [accountsInRepository, setAccountsInRepository] = useState<string[]>(
    []
  );
  const [isLoading, setLoading] = useState(true);
  const [permissionsIsOpen, setPermissionsOpen] = useState(false);

  const roles = [
    {
      name: t('PERMISSIONS.ADMIN'),
      value: 'admin',
    },
    {
      name: t('PERMISSIONS.USER'),
      value: 'member',
    },
  ];

  const fetchUsersInRepository = (allUsersInCompany: Account[]) => {
    repositoryService
      .getUsersInRepository(repoToInvite.companyID, repoToInvite.repositoryID)
      .then((result) => {
        const accountIds: string[] = [];
        const allUsers = cloneDeep(allUsersInCompany);

        result?.data?.content.map((account: Account) => {
          accountIds.push(account.accountID);

          const index = findIndex(allUsers, {
            accountID: account.accountID,
          });

          allUsers[index] = account;
        });
        setAccountsInRepository(accountIds);
        setFilteredUserAccounts(allUsers);
        setUserAccounts(allUsers);
        setLoading(false);
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      });
  };

  const fetchAllUsersInCompany = () => {
    setLoading(true);
    companyService
      .getUsersInCompany(repoToInvite.companyID)
      .then((result) => {
        fetchUsersInRepository(result?.data?.content);
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      });
  };

  const onSearchUser = (search: string) => {
    if (search) {
      const filtered = userAccounts.filter((user) =>
        user.email.toLocaleLowerCase().includes(search.toLocaleLowerCase())
      );

      setFilteredUserAccounts(filtered);
    } else {
      setFilteredUserAccounts(userAccounts);
    }
  };

  const inviteUserToRepository = (account: Account) => {
    repositoryService
      .includeUser(
        repoToInvite.companyID,
        repoToInvite.repositoryID,
        account.email,
        account.role
      )
      .then(() => {
        showSuccessFlash(t('REPOSITORIES_SCREEN.SUCCESS_ADD_USER'));
        setAccountsInRepository([...accountsInRepository, account.accountID]);
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      });
  };

  const removeUserOfRepository = (account: Account) => {
    repositoryService
      .removeUser(
        repoToInvite.companyID,
        repoToInvite.repositoryID,
        account.accountID
      )
      .then(() => {
        showSuccessFlash(t('REPOSITORIES_SCREEN.SUCCESS_REMOVE_USER'));
        const filteredIds = accountsInRepository.filter(
          (item) => item !== account.accountID
        );
        setAccountsInRepository(filteredIds);
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      });
  };

  const handleInviteUser = (isChecked: boolean, account: Account) => {
    if (isChecked) inviteUserToRepository(account);
    else removeUserOfRepository(account);
  };

  const handleChangeUserRole = (role: string, account: Account) => {
    repositoryService
      .updateUserRole(
        repoToInvite.companyID,
        repoToInvite.repositoryID,
        account.accountID,
        role
      )
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      });
  };

  useEffect(() => {
    if (repoToInvite) {
      fetchAllUsersInCompany();
    }
    // eslint-disable-next-line
  }, [repoToInvite]);

  return isVisible ? (
    <Styled.Background>
      <Styled.Wrapper>
        <Styled.Header>
          <Styled.Title>
            {t('REPOSITORIES_SCREEN.INVITE_TO_REPOSITORY')}
          </Styled.Title>

          <Styled.Close name="close" size="24px" onClick={onClose} />
        </Styled.Header>

        <Styled.SubTitle>
          {t('REPOSITORIES_SCREEN.INVITE_USER_BELOW')}
        </Styled.SubTitle>

        <SearchBar
          placeholder={t('REPOSITORIES_SCREEN.SEARCH_USER_EMAIL_BELOW')}
          onSearch={(value) => onSearchUser(value)}
        />

        <Styled.Table>
          <Styled.LoadingWrapper isLoading={isLoading}>
            <Icon name="loading" size="120px" className="loading" />
          </Styled.LoadingWrapper>

          <Styled.Head>
            <Styled.Column>{t('REPOSITORIES_SCREEN.ACTION')}</Styled.Column>
            <Styled.Column>{t('REPOSITORIES_SCREEN.USER')}</Styled.Column>
            <Styled.Column>{t('REPOSITORIES_SCREEN.EMAIL')}</Styled.Column>
            <Styled.Column>{t('REPOSITORIES_SCREEN.PERMISSION')}</Styled.Column>
          </Styled.Head>

          <Styled.Body>
            {!filteredUserAccounts || filteredUserAccounts.length <= 0 ? (
              <Styled.EmptyText>
                {t('REPOSITORIES_SCREEN.NO_USERS_TO_INVITE')}
              </Styled.EmptyText>
            ) : null}

            {filteredUserAccounts.map((account) => (
              <Styled.Row key={account.accountID}>
                <Styled.Cell className="flex-row-center">
                  <Checkbox
                    initialValue={accountsInRepository.includes(
                      account.accountID
                    )}
                    disabled={account.email === currentUser.email}
                    onChangeValue={(value) => handleInviteUser(value, account)}
                  />
                </Styled.Cell>

                <Styled.Cell>{account.username}</Styled.Cell>

                <Styled.Cell>{account.email}</Styled.Cell>

                <Styled.Cell>
                  <Select
                    disabled={
                      account.email === currentUser.email ||
                      !accountsInRepository.includes(account.accountID)
                    }
                    className="select-role"
                    rounded
                    width="150px"
                    keyLabel="name"
                    keyValue="value"
                    initialValue={account.role}
                    options={roles}
                    onChangeValue={(role) =>
                      handleChangeUserRole(role?.value, account)
                    }
                  />
                </Styled.Cell>

                <Styled.HelpIcon
                  name="help"
                  size="18px"
                  onClick={() => setPermissionsOpen(true)}
                />
              </Styled.Row>
            ))}
          </Styled.Body>
        </Styled.Table>
      </Styled.Wrapper>

      <Permissions
        isOpen={permissionsIsOpen}
        onClose={() => setPermissionsOpen(false)}
        rolesType="REPOSITORY"
      />
    </Styled.Background>
  ) : null;
};

export default InviteToRepository;
