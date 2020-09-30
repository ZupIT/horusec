import React, { useState, useEffect } from 'react';
import Styled from './styled';
import HorusecLogo from 'assets/logo/horusec.svg';
import { useTranslation } from 'react-i18next';
import { Icon, Language, Logout, Helper } from 'components';
import { useHistory } from 'react-router-dom';
import { InternalRoute } from 'helpers/interfaces/InternalRoute';
import { find } from 'lodash';
import { isAdminOfCompany } from 'helpers/localStorage/currentCompany';

const SideMenu: React.FC = () => {
  const history = useHistory();
  const { t } = useTranslation();

  const [selectedRoute, setSelectedRoute] = useState<InternalRoute>();
  const [selectedSubRoute, setSelectedSubRoute] = useState<InternalRoute>();

  const routes: InternalRoute[] = [
    {
      name: t('SIDE_MENU.DASHBOARD'),
      icon: 'list',
      type: 'route',
      path: '/home/dashobard',
      subRoutes: [
        {
          name: t('SIDE_MENU.ORGANIZATION'),
          icon: 'grid',
          path: '/home/dashboard/organization',
          type: 'subRoute',
        },
        {
          name: t('SIDE_MENU.REPOSITORIES'),
          icon: 'columns',
          path: '/home/dashboard/repositories',
          type: 'subRoute',
        },
      ],
    },
    {
      name: t('SIDE_MENU.REPOSITORIES'),
      icon: 'columns',
      path: '/home/repositories',
      type: 'route',
    },
    {
      name: t('SIDE_MENU.ORGANIZATION_USERS'),
      icon: 'grid',
      path: '/home/organization-users',
      type: 'route',
      adminOnly: true,
    },
  ];

  useEffect(() => {
    setSelectedRoute(routes[0]);
    setSelectedSubRoute(routes[0].subRoutes[0]);
    // eslint-disable-next-line
  }, []);

  const handleSelectedRoute = (route: InternalRoute) => {
    if (route.type === 'route') {
      setSelectedRoute(route);
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
    if (!route.adminOnly || (route.adminOnly && isAdminOfCompany())) {
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
  };

  const renderSubRoutes = () =>
    find(routes, { path: selectedRoute?.path })?.subRoutes || [];

  return (
    <>
      <Styled.SideMenu>
        <Styled.WrapperLogoRoutes>
          <Styled.Logo src={HorusecLogo} alt="Horusec Logo" />

          <Styled.RoutesList>
            {routes.map((route, index) => renderRoute(route, index))}
          </Styled.RoutesList>
        </Styled.WrapperLogoRoutes>

        <Styled.OptionsWrapper>
          <Helper />

          <Logout />

          <Language />
        </Styled.OptionsWrapper>
      </Styled.SideMenu>

      <Styled.SubMenu isActive={!!selectedRoute?.subRoutes}>
        <Styled.SubRoutesList>
          {renderSubRoutes().map((subRoute, index) => (
            <Styled.SubRouteItem
              key={index}
              isActive={subRoute.path === selectedSubRoute?.path}
              onClick={() => handleSelectedRoute(subRoute)}
            >
              <Icon name={subRoute.icon} size="15" />

              <Styled.RouteName>{subRoute.name}</Styled.RouteName>
            </Styled.SubRouteItem>
          ))}
        </Styled.SubRoutesList>
      </Styled.SubMenu>
    </>
  );
};

export default SideMenu;
