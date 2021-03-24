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

const Signature: React.FC = () => {
  const { t } = useTranslation();

  return (
    <Styled.Wrapper
      href="https://www.zup.com.br"
      rel="noopener noreferrer"
      target="_blank"
    >
      {t('FOOTER.DEVELOPED')} {t('FOOTER.WITH')}
      <Styled.Icon
        ariaLabel={t('FOOTER.LOVE')}
        tabIndex={null}
        name="heart"
        size="12px"
      />
      {t('FOOTER.BY')}
      <Styled.Icon ariaLabel="Zup" tabIndex={null} name="zup" size="35px" />
    </Styled.Wrapper>
  );
};

export default Signature;
