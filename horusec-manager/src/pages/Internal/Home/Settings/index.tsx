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

import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button, Dialog } from 'components';
import Styled from './styled';
import {
  getCurrentUser,
  clearCurrentUser,
} from 'helpers/localStorage/currentUser';
import accountService from 'services/account';

import EditAccount from './Edit';
import ChangePassword from './ChangePassword';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import { clearTokens } from 'helpers/localStorage/tokens';
import { clearCurrentCompany } from 'helpers/localStorage/currentCompany';
import { useHistory } from 'react-router-dom';

const Settings: React.FC = () => {
  const { t } = useTranslation();
  const { email, username } = getCurrentUser();
  const { dispatchMessage } = useResponseMessage();
  const { showSuccessFlash } = useFlashMessage();
  const history = useHistory();

  const [deleteDialogIsOpen, setOpenDeleteDialog] = useState(false);
  const [deleteInProgress, setDeleteInProgress] = useState(false);

  const [editDialogIsOpen, setOpenEditDialog] = useState(false);
  const [changePassDialogIsOpen, setOpenChangePassDialog] = useState(false);

  const handleConfirmDelete = () => {
    setDeleteInProgress(true);
    accountService
      .deleteAccount()
      .then(() => {
        history.replace('/auth');
        clearCurrentUser();
        clearCurrentCompany();
        clearTokens();
        showSuccessFlash(t('SETTINGS_SCREEN.SUCCESS_DELETE'));
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      });
  };

  return (
    <Styled.Wrapper>
      <Styled.Content>
        <Styled.Title>{t('SETTINGS_SCREEN.TITLE')}</Styled.Title>

        <Styled.Table>
          <Styled.Head>
            <Styled.Column>{t('SETTINGS_SCREEN.TABLE.USER')}</Styled.Column>

            <Styled.Column>{t('SETTINGS_SCREEN.TABLE.EMAIL')}</Styled.Column>

            <Styled.Column>{t('SETTINGS_SCREEN.TABLE.ACTION')}</Styled.Column>
          </Styled.Head>

          <Styled.Body>
            <Styled.Row>
              <Styled.Cell>{username}</Styled.Cell>

              <Styled.Cell>{email}</Styled.Cell>

              <Styled.Cell className="row">
                <Button
                  rounded
                  outline
                  opaque
                  text={t('SETTINGS_SCREEN.TABLE.DELETE')}
                  width={90}
                  height={30}
                  icon="delete"
                  onClick={() => setOpenDeleteDialog(true)}
                />

                <Button
                  outline
                  rounded
                  opaque
                  text={t('SETTINGS_SCREEN.TABLE.EDIT')}
                  width={90}
                  height={30}
                  icon="edit"
                  onClick={() => setOpenEditDialog(true)}
                />

                <Button
                  outline
                  rounded
                  opaque
                  text={t('SETTINGS_SCREEN.TABLE.PASSWORD')}
                  width={90}
                  height={30}
                  icon="lock"
                  onClick={() => setOpenChangePassDialog(true)}
                />
              </Styled.Cell>
            </Styled.Row>
          </Styled.Body>
        </Styled.Table>
      </Styled.Content>

      <Dialog
        message={t('SETTINGS_SCREEN.CONFIRM_DELETE')}
        confirmText={t('SETTINGS_SCREEN.YES')}
        loadingConfirm={deleteInProgress}
        defaultButton
        hasCancel
        isVisible={deleteDialogIsOpen}
        onCancel={() => setOpenDeleteDialog(false)}
        onConfirm={handleConfirmDelete}
      />

      <EditAccount
        isVisible={editDialogIsOpen}
        onCancel={() => setOpenEditDialog(false)}
        onConfirm={() => setOpenEditDialog(false)}
      />

      <ChangePassword
        isVisible={changePassDialogIsOpen}
        onCancel={() => setOpenChangePassDialog(false)}
        onConfirm={() => setOpenChangePassDialog(false)}
      />
    </Styled.Wrapper>
  );
};

export default Settings;
