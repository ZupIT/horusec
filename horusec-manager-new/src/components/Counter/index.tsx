import React from 'react';
import Styled from './styled';
import { Icon } from 'components';

interface CounterProps {
  title: string;
  value: number;
  isLoading?: boolean;
}

const Counter: React.FC<CounterProps> = ({ title, value, isLoading }) => {
  return (
    <Styled.Wrapper>
      <Styled.Title>{title}</Styled.Title>

      <Styled.Container>
        {isLoading ? (
          <Icon name="loading" size="100px" />
        ) : (
          <Styled.Count>{value}</Styled.Count>
        )}
      </Styled.Container>
    </Styled.Wrapper>
  );
};

export default Counter;
