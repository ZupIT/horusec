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
  width: 100%;
  padding: 35px 40px 10px 35px;
  overflow-y: scroll;

  ::-webkit-scrollbar {
    width: 10px;
  }

  ::-webkit-scrollbar-thumb {
    background: ${({ theme }) => theme.colors.background.highlight};
    border-radius: 2px;
  }

  ::-webkit-scrollbar-track {
    background-color: ${({ theme }) => theme.colors.scrollbar};
  }
`;

const Row = styled.div`
  display: flex;
  margin: 30px 0;

  div.block {
    &:not(:last-of-type) {
      margin-right: 20px;
    }
  }

  div.max-space {
    width: 100%;
  }

  div.half-space {
    width: 40%;
  }
`;

export default { Wrapper, Row };
