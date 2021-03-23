/**
 * Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import React, {
  InputHTMLAttributes,
  FocusEvent,
  useState,
  ChangeEvent,
  useEffect,
} from 'react';
import isEmpty from 'lodash/isEmpty';
import { Field } from 'helpers/interfaces/Field';
import { IconButton, InputAdornment, TextField } from '@material-ui/core';

import Visibility from '@material-ui/icons/Visibility';
import VisibilityOff from '@material-ui/icons/VisibilityOff';
import { getCurrentTheme } from 'helpers/localStorage/currentTheme';

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  name: string;
  invalidMessage?: string;
  width?: string;
  initialValue?: string;
  validation?: Function;
  onChangeValue?: (params: Field) => any;
  multiline?: boolean;
}

const InputPassword: React.FC<InputProps> = ({
  label,
  invalidMessage,
  name,
  className,
  onChangeValue,
  validation,
  type,
  multiline = false,
  initialValue = undefined,
}) => {
  const [isFocused, setFocused] = useState(false);
  const [inputType, setInputType] = useState(type);
  const [isInvalid, setInvalid] = useState(false);
  const theme = getCurrentTheme();

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
    <div style={{ display: 'block' }} className={className}>
      <TextField
        name={name}
        label={label}
        type={inputType}
        onFocus={handleFocus}
        onBlur={handleFocus}
        id={name}
        onChange={handleOnChange}
        value={initialValue}
        fullWidth
        multiline={multiline}
        error={isInvalid}
        helperText={isInvalid && invalidMessage}
        autoComplete="off"
        InputProps={{
          endAdornment:
            type === 'password' ? (
              <InputAdornment position="end">
                <IconButton
                  aria-label="toggle password visibility"
                  onClick={() =>
                    inputType === 'password'
                      ? setInputType('text')
                      : setInputType('password')
                  }
                  style={{
                    color: theme.colors.input.label,
                  }}
                >
                  {inputType === 'password' ? (
                    <Visibility />
                  ) : (
                    <VisibilityOff />
                  )}
                </IconButton>
              </InputAdornment>
            ) : null,
        }}
      />
    </div>
    // <Styled.Container className={className}>
    //   <Styled.Wrapper>
    //     <Styled.Label isFocused={isFocused} htmlFor={name}>
    //       {label}
    //     </Styled.Label>

    //     <Styled.Input
    //       type={inputType}
    //       isInvalid={isInvalid}
    //       width={width}
    //       onFocus={handleFocus}
    //       onBlur={handleFocus}
    //       id={name}
    //       onChange={handleOnChange}
    //       value={initialValue}
    //     />

    //     {type === 'password' ? (
    //       <Styled.EyeIcon
    //         onClick={() =>
    //           inputType === 'password'
    //             ? setInputType('text')
    //             : setInputType('password')
    //         }
    //         name={inputType === 'password' ? 'view' : 'no-view'}
    //         size="18px"
    //       />
    //     ) : null}
    //   </Styled.Wrapper>

    //   <Styled.Error isInvalid={isInvalid}>{invalidMessage}</Styled.Error>
    // </Styled.Container>
  );
};

export default InputPassword;
