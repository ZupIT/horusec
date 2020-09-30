import React, {
  InputHTMLAttributes,
  FocusEvent,
  useState,
  ChangeEvent,
  useEffect,
} from 'react';
import isEmpty from 'lodash/isEmpty';
import Styled from './styled';
import { Field } from 'helpers/interfaces/Field';

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  name: string;
  invalidMessage?: string;
  width?: string;
  initialValue?: string;
  validation?: Function;
  onChangeValue?: (params: Field) => any;
}

const Input: React.FC<InputProps> = ({
  label,
  invalidMessage,
  name,
  width,
  className,
  onChangeValue,
  validation,
  type,
  initialValue,
}) => {
  const [isFocused, setFocused] = useState(false);
  const [inputType, setInputType] = useState(type);
  const [isInvalid, setInvalid] = useState(false);

  const handleFocus = (event: FocusEvent<HTMLInputElement>) => {
    if (isEmpty(event.currentTarget.value)) {
      setFocused(!isFocused);
    }
  };

  const handleOnChange = (event: ChangeEvent<HTMLInputElement>) => {
    event.preventDefault();
    let isValid;

    if (validation) {
      isValid = validation(event.target.value);

      setInvalid(!isValid);
    } else {
      isValid = true;
    }

    onChangeValue({ value: event.target.value, isValid });
  };

  useEffect(() => {
    if (initialValue) setFocused(true);
  }, [initialValue]);

  return (
    <Styled.Container className={className}>
      <Styled.Wrapper>
        <Styled.Label isFocused={isFocused} htmlFor={name}>
          {label}
        </Styled.Label>

        <Styled.Input
          type={inputType}
          isInvalid={isInvalid}
          width={width}
          onFocus={handleFocus}
          onBlur={handleFocus}
          id={name}
          onChange={handleOnChange}
          value={initialValue}
        />

        {type === 'password' ? (
          <Styled.EyeIcon
            onClick={() =>
              inputType === 'password'
                ? setInputType('text')
                : setInputType('password')
            }
            name={inputType === 'password' ? 'view' : 'no-view'}
            size="18px"
          />
        ) : null}
      </Styled.Wrapper>

      <Styled.Error isInvalid={isInvalid}>{invalidMessage}</Styled.Error>
    </Styled.Container>
  );
};

export default Input;
