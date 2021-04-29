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
import { Form } from 'formik';

const Container = styled(Form)`
  background-color: ${({ theme }) => theme.colors.background.secundary};
  border-radius: 4px;
  padding: 20px;
  display: flex;
  width: min-content;
  align-items: center;
`;

const Wrapper = styled.div`
  min-width: 200px;
  margin-right: 35px;
  transition: all 1s;
`;

const CalendarWrapper = styled(Wrapper)`
  margin-right: 35px;
  margin-top: 3px;
`;

const ApplyButton = styled(Button)`
  margin: 0px 15px;
`;

export default { Container, CalendarWrapper, Wrapper, ApplyButton };
