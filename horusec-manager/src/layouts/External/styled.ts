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

const Wrapper = styled.div`
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  padding-bottom: 50px;

  @media (max-width: 768px) {
    margin-top: 40px;
  }
`;

const LogoContent = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  flex: 1;
  width: 252px;
`;

const Content = styled.div`
  margin-top: 60px;
`;

const Logo = styled.img`
  width: 266px;

  position: absolute;
  top: 30%;
  left: 50%;
  transform: translate(-50%, -50%);
`;

const Footer = styled.footer`
  position: relative;
  display: flex;
  flex-direction: row-reverse;
  align-items: center;
  justify-content: center;
  width: 100%;

  @media (max-width: 768px) {
    flex-direction: column-reverse;
    margin-top: 30px;
  }
`;

const LanguageWrapper = styled.div`
  position: absolute;
  left: 10%;

  @media (max-width: 768px) {
    position: relative;
    left: 0;
    margin-bottom: 40px;
  }
`;

export default {
  Wrapper,
  Logo,
  Content,
  Footer,
  LanguageWrapper,
  LogoContent,
};
