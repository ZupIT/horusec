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
import Select from 'components/Select';

interface RouterItemProps {
  isActive: boolean;
}

interface SubMenuProps {
  isActive: boolean;
}

const SideMenu = styled.div`
  background-color: ${({ theme }) => theme.colors.background.primary};
  min-width: 165px;
  max-width: 165px;
  display: flex;
  flex-direction: column;
  z-index: 2;
`;

const WrapperLogoRoutes = styled.nav`
  flex: 1;
`;

const OptionsList = styled.ul`
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

const RoutesList = styled.ul`
  margin-top: 20px;
`;

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

const SubMenu = styled.nav<SubMenuProps>`
  background-color: ${({ theme }) => theme.colors.background.secundary};
  min-width: 180px;
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

const OptionItem = styled.li``;

const Config = styled(Icon)`
  width: 30px;
  cursor: pointer;
  margin: 0 0 20px 15px;
  nav-index: 1;
`;

const SelectWrapper = styled.div`
  margin-left: 17px;
`;

const SelectWorkspace = styled(Select)`
  border: none !important;
  max-width: 140px;

  div.options-list {
    width: 200px !important;
  }
`;

export default {
  SideMenu,
  Logo,
  RoutesList,
  RouteItem,
  RouteName,
  WrapperLogoRoutes,
  OptionsList,
  SubMenu,
  SubRoutesList,
  SubRouteItem,
  OptionItem,
  Config,
  SelectWorkspace,
  SelectWrapper,
};
