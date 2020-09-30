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

interface WrapperProps {
  width?: number;
}

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

const Wrapper = styled.div<WrapperProps>`
  background-color: ${({ theme }) => theme.colors.dialog.background};
  width: ${({ width }) => (width ? `${width}px` : '410px')};
  padding: 30px 40px;
  border-radius: 4px;
`;

const Content = styled.div<WrapperProps>`
  margin-top: 35px;
`;

const Message = styled.span`
  color: ${({ theme }) => theme.colors.dialog.text};
  font-size: ${({ theme }) => theme.metrics.fontSize.xlarge};
  line-height: 22px;
`;

const ButtonsWrapper = styled.div`
  display: flex;
  justify-content: space-around;
  margin-top: 35px;
`;

export default { Background, Wrapper, Message, ButtonsWrapper, Content };
