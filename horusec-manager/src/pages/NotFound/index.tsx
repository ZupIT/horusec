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
import Styled from './styled';
import { Footer, Logout, Language } from 'components';
import { useTranslation } from 'react-i18next';
import { tokenIsExpired } from 'helpers/localStorage/currentUser';

import HorusecLogo from 'assets/logo/horusec.svg';
import NotFoundImg from 'assets/svg/not_found.svg';
import { useHistory } from 'react-router-dom';

const NotFound: React.FC = () => {
  const { t } = useTranslation();
  const history = useHistory();

  return (
    <>
      <Styled.Content>
        <Styled.SideBar>
          <Styled.Logo src={HorusecLogo} alt="Horusec Logo" />

          <Styled.SettingsWrapper>
            {tokenIsExpired() ? null : <Logout />}

            <Language />
          </Styled.SettingsWrapper>
        </Styled.SideBar>

        <Styled.NotFoundImg src={NotFoundImg} />

        <Styled.Message>{t('NOT_FOUND_SCREEN.ERROR')}</Styled.Message>

        <Styled.Message>{t('NOT_FOUND_SCREEN.MESSAGE')}</Styled.Message>

        <Styled.BackBtn
          rounded
          text={t('NOT_FOUND_SCREEN.BACK')}
          onClick={() => history.replace('/home')}
        />
      </Styled.Content>

      <Footer />
    </>
  );
};

export default NotFound;
