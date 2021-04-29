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
import { Input, Select, Icon } from 'components';

const Form = styled.form`
  display: flex;
  flex-direction: column;
`;

const Field = styled(Input)`
  display: block;
  margin-right: 20px;
`;

const Label = styled.label`
  font-size: ${({ theme }) => theme.metrics.fontSize.medium};
  color: ${({ theme }) => theme.colors.text.secundary};
  margin: 22px 0;
`;

const Wrapper = styled.div`
  display: flex;
  align-items: center;
  margin-bottom: 25px;
`;

const URLSelect = styled(Select)`
  opacity: 1 !important;
  margin-right: 20px;

  div {
    color: ${({ theme }) => theme.colors.text.primary};
  }
`;

const OptionIcon = styled(Icon)`
  margin-right: 10px;
`;

export default {
  Form,
  Field,
  Label,
  Wrapper,
  URLSelect,
  OptionIcon,
};
