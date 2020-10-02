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

import styled, { css } from 'styled-components';
import { Icon } from 'components';

interface RouterItemProps {
  isActive: boolean;
}

interface SubMenuProps {
  isActive: boolean;
}

const SideMenu = styled.div`
  background-color: ${({ theme }) => theme.colors.background.primary};
  max-width: 135px;
  display: flex;
  flex-direction: column;
  z-index: 2;
`;

const WrapperLogoRoutes = styled.div`
  flex: 1;
`;

const OptionsWrapper = styled.div`
  display: flex;
  flex-direction: column;
  padding: 20px 0px 20px 7.5px;
`;

const Logo = styled.img`
  display: block;
  margin: 24px 17px;
  width: 100px;
  height: 22px;
`;

const RoutesList = styled.ul``;

const SubRoutesList = styled(RoutesList)`
  margin-top: 50px;
`;

const RouteItem = styled.li<RouterItemProps>`
  cursor: pointer;
  color: ${({ theme }) => theme.colors.text.primary};
  font-size: ${({ theme }) => theme.metrics.fontSize.small};
  padding: 17px;
  display: flex;
  align-items: center;
  justify-content: flex-start;
  position: relative;
  transition: background-color 0.6s;

  :hover {
    background-color: ${({ theme }) => theme.colors.background.secundary};
  }

  ${({ isActive }) =>
    isActive &&
    css`
      background-color: ${({ theme }) => theme.colors.background.secundary};
    `};
`;

const SubRouteItem = styled(RouteItem)`
  :hover {
    background-color: ${({ theme }) => theme.colors.background.highlight};
  }

  ${({ isActive }) =>
    isActive &&
    css`
      background-color: ${({ theme }) => theme.colors.background.highlight};
    `};
`;

const RouteName = styled.span`
  display: block;
  margin-left: 13px;
`;

const SubMenu = styled.div<SubMenuProps>`
  background-color: ${({ theme }) => theme.colors.background.secundary};
  height: 96.3vh;
  min-width: 160px;
  top: 0;
  left: -165px;
  transition: left 0.6s;
  position: absolute;

  ${({ isActive }) =>
    isActive &&
    css`
      left: 0;
      position: relative;
    `};
`;

const Back = styled(Icon)`
  margin: 20px 0px 0px 17px;
  width: 30px;
  cursor: pointer;
`;

export default {
  SideMenu,
  Logo,
  RoutesList,
  RouteItem,
  RouteName,
  WrapperLogoRoutes,
  OptionsWrapper,
  SubMenu,
  SubRoutesList,
  SubRouteItem,
  Back,
};
