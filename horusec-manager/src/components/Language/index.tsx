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

import React, { useRef, useState } from 'react';

import Styled from './styled';
import Icon from 'components/Icon';
import useLanguage from 'helpers/hooks/useLanguage';
import { useTheme } from 'styled-components';
import { useTranslation } from 'react-i18next';
import useOutsideClick from 'helpers/hooks/useClickOutside';

const Language: React.FC = () => {
  const { t } = useTranslation();
  const listLanguagesRef = useRef(null);

  const [showList, setShowList] = useState(false);
  const [showButton, setShowButton] = useState(true);

  const { colors } = useTheme();
  const { allLanguages, currentLanguage, setUserLanguage } = useLanguage();

  const handleShowList = () => {
    setShowList(!showList);
    setShowButton(!showButton);

    setTimeout(() => {
      listLanguagesRef?.current?.focus();
    }, 1000);
  };

  const handleCurrentLanguage = (lang: any, event: React.KeyboardEvent) => {
    if (!event || event.keyCode === 13 || event.keyCode === 32) {
      setUserLanguage(lang);
      handleShowList();
    }
  };

  useOutsideClick(listLanguagesRef, () => {
    if (listLanguagesRef) handleShowList();
  });

  return (
    <Styled.Wrapper>
      {!showButton || (
        <Styled.Button
          onClick={handleShowList}
          tabIndex={0}
          id="language"
          aria-expanded="true"
          aria-label={`${t('SELECT_LANGUAGE.CHANGE')}
            ${t('SELECT_LANGUAGE.CURRENT')} ${currentLanguage?.description}`}
        >
          <Styled.CurrentLanguage>
            {currentLanguage?.name}
          </Styled.CurrentLanguage>

          <Icon name="down-arrow" color={colors.text.primary} size="14px" />
        </Styled.Button>
      )}

      {!showList || (
        <Styled.LanguagesList ref={listLanguagesRef}>
          {allLanguages.map((language, index) => (
            <Styled.LanguageItem
              key={index}
              onClick={() => handleCurrentLanguage(language, null)}
              onKeyDown={(e) => handleCurrentLanguage(language, e)}
              aria-expanded="true"
              aria-label={language.description}
              tabIndex={0}
              id={language.i18nValue}
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
