import styled from 'styled-components';

export const Menu = styled.ul`
  padding: 0;
  margin: 0;
  display: flex;
`;

export const MenuItem = styled.li`
  a {
    font-family: Lato;
    font-style: normal;
    font-weight: normal;
    font-size: 16px;
    line-height: 24px;
    color: #0E1E33;

  }
`;

export const Sidebar = styled.nav`
  width: 100%;
  position: fixed;
  top: 0;
  left: 0;
  box-shadow: 0 2px 4px 0 rgba(0, 0, 0, 0.5);
  padding: 24px;
  z-index: 1;
  background-color: #fff;
`;

export const MobileMenu = styled.ul``;

export const MobileItem = styled.li`
  margin-top: 24px;

  > * {
    font-size: 14px;
    line-height: 21px;
    color: #616466;
    text-decoration: none;
    cursor: pointer;

    &:hover {
      text-decoration: none;
    }
  }

  &:first-child {
    margin-top: 0;
  }
`;
