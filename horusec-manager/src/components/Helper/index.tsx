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

import React from 'react';
import { useTranslation } from 'react-i18next';
import Styled from './styled';

const Helper: React.FC = () => {
  const { t } = useTranslation();

  return (
    <Styled.HelpIcon
      ariaLabel={t('SIDE_MENU.HELPER')}
      tabIndex={0}
      name="help"
      size="15px"
    />
  );
};

export default Helper;
