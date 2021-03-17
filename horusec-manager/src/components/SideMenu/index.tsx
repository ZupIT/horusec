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
import Styled from './styled';
import HorusecLogo from 'assets/logos/horusec.svg';
import { useTranslation } from 'react-i18next';
import { Icon, Language, Logout, Helper, Select } from 'components';
import { useHistory } from 'react-router-dom';
import { InternalRoute } from 'helpers/interfaces/InternalRoute';
import { find } from 'lodash';
import ReactTooltip from 'react-tooltip';
import useWorkspace from 'helpers/hooks/useWorkspace';
import { getCurrentConfig } from 'helpers/localStorage/horusecConfig';
import { authTypes } from 'helpers/enums/authTypes';
import { Workspace } from 'helpers/interfaces/Workspace';

const SideMenu: React.FC = () => {
  const history = useHistory();
  const {
    currentWorkspace,
    allWorkspaces,
    handleSetCurrentWorkspace,
  } = useWorkspace();
  const { t } = useTranslation();
  const { authType, disabledBroker } = getCurrentConfig();

  const [selectedRoute, setSelectedRoute] = useState<InternalRoute>();
  const [selectedSubRoute, setSelectedSubRoute] = useState<InternalRoute>();

  const routes: InternalRoute[] = [
    {
      name: t('SIDE_MENU.DASHBOARD'),
      icon: 'pie',
      type: 'route',
      path: '/home/dashboard',
      roles: ['admin', 'member'],
      subRoutes: [
        {
          name: t('SIDE_MENU.WORKSPACE'),
          icon: 'grid',
          path: '/home/dashboard/workspace',
          type: 'subRoute',
          roles: ['admin'],
        },
        {
          name: t('SIDE_MENU.REPOSITORIES'),
          icon: 'columns',
          path: '/home/dashboard/repositories',
          type: 'subRoute',
          roles: ['admin', 'member'],
        },
      ],
    },
    {
      name: t('SIDE_MENU.VULNERABILITIES'),
      icon: 'shield',
      path: '/home/vulnerabilities',
      type: 'route',
      roles: ['admin', 'member'],
    },
    {
      name: t('SIDE_MENU.REPOSITORIES'),
      icon: 'columns',
      path: '/home/repositories',
      type: 'route',
      roles: ['admin', 'member'],
    },
    {
      name: t('SIDE_MENU.WEBHOOK'),
      icon: 'webhook',
      path: '/home/webhooks',
      type: 'route',
      roles: ['admin'],
      rule: () => !disabledBroker,
    },
  ];

  const handleSelectedRoute = (route: InternalRoute) => {
    if (route.type === 'route') {
      setSelectedRoute((state) => {
        if (
          state &&
          state?.subRoutes &&
          route?.subRoutes &&
          !selectedSubRoute
        ) {
          return null;
        }
        return route;
      });
      setSelectedSubRoute(null);

      if (!route?.subRoutes) {
        history.push(route.path);
      }
    } else {
      setSelectedSubRoute(route);
      history.push(route.path);
    }
  };

  const renderRoute = (route: InternalRoute, index: number) => {
    if (route.roles.includes(currentWorkspace?.role)) {
      if (!route?.rule || (route?.rule && route?.rule())) {
        return (
          <Styled.RouteItem
            key={index}
            isActive={route.path === selectedRoute?.path}
            onClick={() => handleSelectedRoute(route)}
          >
            <Icon name={route.icon} size="15" />

            <Styled.RouteName>{route.name}</Styled.RouteName>
          </Styled.RouteItem>
        );
      }
    }
  };

  const goToSettings = () => {
    history.replace('/home/settings');
    setSelectedRoute(null);
    setSelectedSubRoute(null);
  };

  const fetchSubRoutes = () =>
    find(routes, { path: selectedRoute?.path })?.subRoutes || [];

  const renderSubRoute = (subRoute: InternalRoute, index: number) => {
    if (subRoute.roles.includes(currentWorkspace?.role)) {
      return (
        <Styled.SubRouteItem
          key={index}
          isActive={subRoute.path === selectedSubRoute?.path}
          onClick={() => handleSelectedRoute(subRoute)}
        >
          <Icon name={subRoute.icon} size="15" />

          <Styled.RouteName>{subRoute.name}</Styled.RouteName>
        </Styled.SubRouteItem>
      );
    }
  };

  const handleSelectedWorkspace = (workspace: Workspace) => {
    handleSetCurrentWorkspace(workspace);
    history.replace('/home/dashboard');
    setSelectedRoute(null);
    setSelectedSubRoute(null);
  };

  return (
    <>
      <Styled.SideMenu>
        <Styled.WrapperLogoRoutes>
          <Styled.Logo src={HorusecLogo} alt="Horusec Logo" />

          {allWorkspaces && allWorkspaces.length > 0 ? (
            <Styled.SelectWrapper>
              <Select
                options={allWorkspaces}
                initialValue={currentWorkspace}
                onChangeValue={(value) => handleSelectedWorkspace(value)}
                keyLabel="name"
                title="WORKSPACE"
                hasSearch
                background="none"
                fixedItemTitle={t('SIDE_MENU.MANAGE_WORKSPACES')}
                onClickFixedItem={() => history.push('/home/workspaces')}
              />
            </Styled.SelectWrapper>
          ) : null}

          <Styled.RoutesList>
            {routes.map((route, index) => renderRoute(route, index))}
          </Styled.RoutesList>
        </Styled.WrapperLogoRoutes>

        <Styled.OptionsWrapper>
          {authType === authTypes.HORUSEC ? (
            <Styled.Option
              dataFor="side-options"
              dataTip={t('SIDE_MENU.CONFIG')}
              name="config"
              size="15"
              onClick={goToSettings}
            />
          ) : null}

          <Helper />

          <Logout />

          <Language />

          <ReactTooltip id="side-options" place="top" type="dark" insecure />
        </Styled.OptionsWrapper>
      </Styled.SideMenu>

      <Styled.SubMenu isActive={!!selectedRoute?.subRoutes}>
        <Styled.SubRoutesList>
          {fetchSubRoutes().map((subRoute, index) =>
            renderSubRoute(subRoute, index)
          )}
        </Styled.SubRoutesList>
      </Styled.SubMenu>
    </>
  );
};

export default SideMenu;
