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
import { Input, Button } from 'components';

interface ItemProps {
  isInvalid?: boolean;
}

const Container = styled.div`
  display: block;
  margin-top: 200px;
`;

const SubTitle = styled.h2`
  color: ${({ theme }) => theme.colors.text.primary};
  font-weight: normal;
  align-self: flex-start;
  font-size: ${({ theme }) => theme.metrics.fontSize.large};
  margin-bottom: 15px;
`;

const PassRequirements = styled.div`
  margin-bottom: 40px;
  display: flex;
  flex-direction: column;
`;

const Info = styled.p`
  color: ${({ theme }) => theme.colors.text.opaque};
  font-size: ${({ theme }) => theme.metrics.fontSize.medium};
  align-self: flex-start;
  margin: 10px 0;
  font-weight: 600;
`;

const Item = styled.span<ItemProps>`
  color: ${({ theme }) => theme.colors.text.opaque};
  font-size: ${({ theme }) => theme.metrics.fontSize.small};
  margin: 0 0 5px 10px;

  ${({ isInvalid }) =>
    isInvalid &&
    css`
      color: ${({ theme }) => theme.colors.input.error};
    `};
`;

const Form = styled.form`
  display: flex;
  flex-direction: column;
`;

const Field = styled(Input)`
  margin-bottom: 45px;
`;

const Submit = styled(Button)`
  display: block;
`;

const BackToLogin = styled(Button)`
  margin-top: 15px;
`;

const Subject = styled.span`
  color: ${({ theme }) => theme.colors.text.secundary};
  font-size: ${({ theme }) => theme.metrics.fontSize.xsmall};
  margin-top: 35px;
`;

export default {
  Form,
  PassRequirements,
  Item,
  SubTitle,
  Field,
  Submit,
  BackToLogin,
  Subject,
  Info,
  Container,
};
