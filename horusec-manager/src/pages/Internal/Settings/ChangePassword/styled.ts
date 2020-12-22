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
import { Input } from 'components';

interface ItemProps {
  isInvalid?: boolean;
}

const Form = styled.form`
  display: flex;
  flex-direction: column;
`;

const Field = styled(Input)`
  margin-top: 25px;
  margin-bottom: 10px;
`;

const PassRequirements = styled.div`
  margin-bottom: 10px;
  display: block;
`;

const Info = styled.p`
  color: ${({ theme }) => theme.colors.text.opaque};
  font-size: ${({ theme }) => theme.metrics.fontSize.medium};
  align-self: flex-start;
  margin: 10px 0;
  font-weight: 600;
`;

const Item = styled.li<ItemProps>`
  color: ${({ theme }) => theme.colors.text.opaque};
  font-size: ${({ theme }) => theme.metrics.fontSize.small};
  margin: 0 0 5px 10px;

  ${({ isInvalid }) =>
    isInvalid &&
    css`
      color: ${({ theme }) => theme.colors.input.error};
    `};
`;

export default {
  Form,
  Field,
  Item,
  Info,
  PassRequirements,
};
