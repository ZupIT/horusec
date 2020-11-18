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

import React from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from 'components';
import Styled from './styled';
import { getCurrentUser } from 'helpers/localStorage/currentUser';

const Settings: React.FC = () => {
  const { t } = useTranslation();
  const { email, username } = getCurrentUser();

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
                  onClick={() => console.log('delete')}
                />

                <Button
                  outline
                  rounded
                  opaque
                  text={t('SETTINGS_SCREEN.TABLE.EDIT')}
                  width={90}
                  height={30}
                  icon="edit"
                  onClick={() => console.log('edit')}
                />

                <Button
                  outline
                  rounded
                  opaque
                  text={t('SETTINGS_SCREEN.TABLE.PASSWORD')}
                  width={90}
                  height={30}
                  icon="lock"
                  onClick={() => console.log('senha')}
                />
              </Styled.Cell>
            </Styled.Row>
          </Styled.Body>
        </Styled.Table>
      </Styled.Content>
    </Styled.Wrapper>
  );
};

export default Settings;
