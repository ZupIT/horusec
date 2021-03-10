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

import styled from 'styled-components';
import { Icon } from 'components';

const Background = styled.div`
  width: 100vw;
  height: 100vh;
  position: fixed;
  background-color: ${({ theme }) => theme.colors.dialog.backgroundScreen};
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 3;
  top: 0;
  left: 0;
`;

const Wrapper = styled.div`
  background-color: ${({ theme }) => theme.colors.dialog.background};
  width: 580px;
  padding: 30px 50px;
  border-radius: 4px;
  overflow: visible;
`;

const Header = styled.div`
  display: flex;
  justify-content: space-between;
  margin-bottom: 30px;
`;

const TitleWrapper = styled.div`
  display: flex;
  align-items: center;
`;

const Title = styled.div`
  color: ${({ theme }) => theme.colors.text.primary};
  font-size: ${({ theme }) => theme.metrics.fontSize.xlarge};
  line-height: 22px;
  margin-left: 10px;
`;

const Close = styled(Icon)`
  transition-duration: 0.5s;
  transition-property: transform;

  :hover {
    transform: rotate(90deg);
    -webkit-transform: rotate(90deg);
    cursor: pointer;
  }
`;

const Subtitle = styled.h4`
  color: ${({ theme }) => theme.colors.text.opaque};
  font-weight: 600;
  font-size: ${({ theme }) => theme.metrics.fontSize.medium};
`;

const List = styled.ul`
  margin: 10px 0px 10px 30px;
`;

const Item = styled.li`
  color: ${({ theme }) => theme.colors.text.opaque};
  font-size: ${({ theme }) => theme.metrics.fontSize.small};
  margin: 3px 0;
`;

export default {
  Background,
  Wrapper,
  Title,
  Header,
  Close,
  TitleWrapper,
  Subtitle,
  List,
  Item,
};
