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
        <Styled.Button onClick={handleShowList}>
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
