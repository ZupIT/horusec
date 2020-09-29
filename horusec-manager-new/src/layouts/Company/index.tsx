import React from 'react';
import Styled from './styled';
import { Signature, Logout, Language } from 'components';

const CompanyLayout = ({ children }: { children: JSX.Element }) => {
  return (
    <Styled.Wrapper>
      <Styled.Container>
        <Styled.Content>{children}</Styled.Content>
      </Styled.Container>

      <Styled.Footer>
        <Signature />

        <Styled.LanguageWrapper>
          <Logout />

          <Language />
        </Styled.LanguageWrapper>
      </Styled.Footer>
    </Styled.Wrapper>
  );
};

export default CompanyLayout;
