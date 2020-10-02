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
import { Button } from 'components';

const Content = styled.section`
  width: 100%;
  height: calc(100vh - 36px);
  position: relative;
  display: flex;
  justify-content: center;
  align-items: center;
  flex-direction: column;
`;

const SideBar = styled.section`
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  height: calc(100vh - 36px);
  position: absolute;
  padding: 30px 15px;
  left: 0;
  top: 0;
`;

const Logo = styled.img`
  display: block;
  width: 100px;
  height: 22px;
`;

const NotFoundImg = styled.img`
  display: block;
  width: 460px;
  height: 300px;
  margin-bottom: 35px;
`;

const SettingsWrapper = styled.div`
  display: block;
`;

const Message = styled.span`
  display: block;
  max-width: 700px;
  font-size: ${({ theme }) => theme.metrics.fontSize.big};
  color: ${({ theme }) => theme.colors.text.secundary};
  text-align: center;
`;

const BackBtn = styled(Button)`
  margin-top: 70px;
`;

export default {
  Content,
  SideBar,
  Logo,
  SettingsWrapper,
  NotFoundImg,
  Message,
  BackBtn,
};
