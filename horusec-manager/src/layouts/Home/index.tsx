import React from 'react';
import { SideMenu, Footer } from 'components';
import Styled from './styled';

function HomeLayout({ children }: { children: JSX.Element }) {
  return (
    <>
      <Styled.Wrapper>
        <SideMenu />

        {children}
      </Styled.Wrapper>

      <Footer />
    </>
  );
}

export default HomeLayout;
