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
import { Input, Button } from 'components';
import { Form as FormMik } from 'formik';

const Form = styled(FormMik)`
  display: flex;
  flex-direction: column;
`;

const SubTitle = styled.h2`
  color: ${({ theme }) => theme.colors.text.primary};
  font-weight: normal;
  align-self: flex-start;
  font-size: ${({ theme }) => theme.metrics.fontSize.large};
  margin-bottom: 25px;
`;

const Field = styled(Input)`
  margin-top: 20px;
`;

const Submit = styled(Button)`
  margin-top: 45px;
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
  SubTitle,
  Field,
  Submit,
  BackToLogin,
  Subject,
};
