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

const Field = styled(Input)`
  margin: 25px 0;
`;

const ForgotPass = styled.a`
  color: ${({ theme }) => theme.colors.text.link};
  font-size: ${({ theme }) => theme.metrics.fontSize.small};
  align-self: flex-start;
  cursor: pointer;
  transition: 0.2s;
  margin-top: 20px;

  :hover {
    transform: scale(1.1);
  }
`;

const Submit = styled(Button)`
  margin-top: 35px;
`;

const Register = styled(Button)`
  margin-top: 15px;
`;

export default {
  Form,
  Field,
  ForgotPass,
  Submit,
  Register,
};
