import React, { InputHTMLAttributes } from 'react';
import { Icon } from 'components';
import Styled from './styled';

interface Props extends InputHTMLAttributes<HTMLInputElement> {
  onSearch: (value: string) => void;
  placeholder: string;
}

const SearchBar: React.FC<Props> = ({ placeholder, onSearch, ...rest }) => {
  return (
    <Styled.Wrapper>
      <Icon name="search" size="14px" />

      <Styled.Input
        {...rest}
        placeholder={placeholder}
        onChange={(event) => onSearch(event.target.value)}
      />
    </Styled.Wrapper>
  );
};

export default SearchBar;
