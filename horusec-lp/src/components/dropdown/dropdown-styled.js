import styled from 'styled-components';

export const Dropdown = styled.div`
  position: relative;
`;

export const Label = styled.span`
  font-family: Lato;
  font-size: 16px;
  line-height: 24px;
  color: #0E1E33;
`;

export const Action = styled.span``;

export const Options = styled.ul`
  position: absolute;
  top: 40px;
  right: 0;
  z-index: 100;
  opacity: ${(props) => (props.isItOpen ? 1 : 0)};
  border-radius: 4.8px;
  border: 1px solid rgba(200, 199, 204, 0.5);
  box-shadow: 0 4px 30px 0 rgba(0, 0, 0, 0.2);
  background-color: #ffffff;
  margin: 0;
`;

export const OptionItem = styled.li`
  font-family: Lato;
  font-size: 14px;
  padding: 15px 20px;
  cursor: pointer;
  border-bottom: 1px solid rgba(200, 199, 204, 0.5);

  &:hover {
    text-decoration: underline;
  }

  &:last-child {
    border-bottom: 0;
  }
`;
