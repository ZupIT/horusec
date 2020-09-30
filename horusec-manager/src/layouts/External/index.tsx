import React from 'react';
import Styled from './styled';
import HorusecLogo from 'assets/logo/horusec.svg';
import { Signature, Language } from 'components';

function ExternalLayout({ children }: { children: JSX.Element }) {
  return (
    <Styled.Wrapper>
      <Styled.Content>
        <Styled.Logo src={HorusecLogo} alt="Horusec Logo" />

        {children}
      </Styled.Content>

      <Styled.Footer>
        <Signature />

        <Styled.LanguageWrapper>
          <Language />
        </Styled.LanguageWrapper>
      </Styled.Footer>
    </Styled.Wrapper>
  );
}

export default ExternalLayout;
