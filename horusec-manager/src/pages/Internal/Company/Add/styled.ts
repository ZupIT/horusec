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

const Title = styled.h1`
  font-weight: normal;
  font-size: ${({ theme }) => theme.metrics.fontSize.xxlarge};
  color: ${({ theme }) => theme.colors.text.primary};
  align-self: flex-start;
`;

const SubTitle = styled.h3`
  font-weight: normal;
  font-size: ${({ theme }) => theme.metrics.fontSize.medium};
  color: ${({ theme }) => theme.colors.text.secundary};
  align-self: flex-start;
  margin-bottom: 25px;
  margin-top: 30px;
`;

const Form = styled.form`
  display: block;
`;

const Btn = styled(Button)`
  display: block;
  margin-right: 30px;
`;

const OptionsWrapper = styled.div`
  display: flex;
  justify-content: center;
  margin-top: 40px;
`;

const Wrapper = styled.div`
  display: flex;
  align-items: flex-end;
  margin-top: 25px;
  width: 100%;
`;

const Label = styled.label`
  font-size: ${({ theme }) => theme.metrics.fontSize.medium};
  color: ${({ theme }) => theme.colors.text.secundary};
  width: 100px;
`;

export default {
  Title,
  SubTitle,
  Form,
  OptionsWrapper,
  Btn,
  Wrapper,
  Label,
};
