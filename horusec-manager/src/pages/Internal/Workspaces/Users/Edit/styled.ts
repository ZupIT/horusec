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
import { Input, Icon } from 'components';

const SubTitle = styled.h3`
  font-weight: normal;
  font-size: ${({ theme }) => theme.metrics.fontSize.small};
  color: ${({ theme }) => theme.colors.text.secundary};
`;

const Form = styled.form`
  display: flex;
  flex-direction: column;
`;

const Field = styled(Input)`
  margin-top: 25px;
  margin-bottom: 10px;
`;

const RoleWrapper = styled.div`
  display: flex;
  align-items: center;
`;

const HelpIcon = styled(Icon)`
  margin-left: 10px;
  cursor: pointer;

  :hover {
    transform: scale(1.2);
  }
`;

const EmailOfUser = styled.span`
  display: block;
  font-size: ${({ theme }) => theme.metrics.fontSize.medium};
  color: ${({ theme }) => theme.colors.text.primary};
  margin-top: 10px;
  margin-bottom: 20px;
`;

export default {
  SubTitle,
  Form,
  Field,
  RoleWrapper,
  HelpIcon,
  EmailOfUser,
};
