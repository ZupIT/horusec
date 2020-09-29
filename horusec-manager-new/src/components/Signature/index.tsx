import React from 'react';

import Styled from './styled';

const Signature: React.FC = () => {
  return (
    <Styled.Wrapper
      href="https://www.zup.com.br"
      rel="noopener noreferrer"
      target="_blank"
    >
      Developed with <Styled.Icon name="heart" size="12px" />
      by <Styled.Icon name="zup" size="35px" />
    </Styled.Wrapper>
  );
};

export default Signature;
