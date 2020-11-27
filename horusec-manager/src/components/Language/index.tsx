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

import React, { useState } from 'react';

import Styled from './styled';
import Icon from 'components/Icon';
import useLanguage from 'helpers/hooks/useLanguage';
import { useTheme } from 'styled-components';

const Language: React.FC = () => {
  const [showList, setShowList] = useState(false);
  const [showButton, setShowButton] = useState(true);

  const { colors } = useTheme();
  const { allLanguages, currentLanguage, setUserLanguage } = useLanguage();

  const handleShowList = () => {
    setShowList(!showList);
    setShowButton(!showButton);
  };

  const handleCurrentLanguage = (lang: any) => {
    setUserLanguage(lang);
    handleShowList();
  };

  return (
    <Styled.Wrapper>
      {!showButton || (
        <Styled.Button id="language" onClick={handleShowList}>
          <Styled.CurrentLanguage>
            {currentLanguage?.name}
          </Styled.CurrentLanguage>

          <Icon name="down-arrow" color={colors.text.primary} size="14px" />
        </Styled.Button>
      )}

      {!showList || (
        <Styled.LanguagesList>
          {allLanguages.map((language, index) => (
            <Styled.LanguageItem
              key={index}
              id={language.i18nValue}
              onClick={() => handleCurrentLanguage(language)}
            >
              <Icon name={language.icon} size="30px" />

              {language.name}
            </Styled.LanguageItem>
          ))}
        </Styled.LanguagesList>
      )}
    </Styled.Wrapper>
  );
};

export default Language;
