import styled from 'styled-components';

export const Cookie = styled.div`
  padding: 24px;
  position: relative;
  border-radius: 12px;
`;

export const Actions = styled.ul`
  position: absolute;
  top: 15.21px;
  right: 15.21px;
  display: flex;
`;

export const ActionItem = styled.li`
  margin-left: 10px;
  cursor: pointer;

  &:first-child {
    margin-left: 0;
  }
`;

export const Text = styled.p`
  font-family: Dosis;
  font-weight: bold;
  font-size: 16px;
  line-height: 23px;
  font-feature-settings: 'liga' off;
  color: #ffffff;

  a {
    color: #ffffff;
    text-decoration: underline;
  }
`;
