import React from 'react';
import Styled from './styled';

interface Props {
  isVisible: boolean;
  message: string;
}

const Flash: React.FC<Props> = ({ isVisible, message }) => {
  return (
    <>
      <Styled.Wrapper isVisible={isVisible}>
        <Styled.Text>{message}</Styled.Text>
      </Styled.Wrapper>
    </>
  );
};

export default Flash;
