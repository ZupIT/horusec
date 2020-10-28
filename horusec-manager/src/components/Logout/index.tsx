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
import useAuth from 'helpers/hooks/useAuth';
import { useHistory } from 'react-router-dom';
import ReactTooltip from 'react-tooltip';
import { useTranslation } from 'react-i18next';

const Logout: React.FC = () => {
  const history = useHistory();
  const { logout } = useAuth();
  const { t } = useTranslation();

  const handleLogout = () => {
    logout().then(() => history.replace('/auth'));
  };

  return (
    <>
      <Styled.LogoutIcon
        onClick={() => handleLogout()}
        size="16px"
        name="logout"
        dataFor="logout"
        dataTip={t('SIDE_MENU.LOGOUT')}
      />

      <ReactTooltip id="logout" place="top" type="dark" insecure />
    </>
  );
};

export default Logout;
