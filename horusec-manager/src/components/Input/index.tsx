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
import Styled from './styled';
import { Field } from 'helpers/interfaces/Field';
import { useTranslation } from 'react-i18next';

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
  initialValue = undefined,
}) => {
  const [isFocused, setFocused] = useState(false);
  const [inputType, setInputType] = useState(type);
  const [isInvalid, setInvalid] = useState(false);
  const { t } = useTranslation();

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
          aria-describedby={`${name}-error`}
        />

        {type === 'password' ? (
          <Styled.EyeIcon
            onClick={() =>
              inputType === 'password'
                ? setInputType('text')
                : setInputType('password')
            }
            name={inputType === 'password' ? 'view' : 'no-view'}
            ariaLabel={t('GENERAL.PASS_VISIBILITY')}
            size="18px"
            tabIndex={0}
          />
        ) : null}
      </Styled.Wrapper>

      <Styled.Error
        id={`${name}-error`}
        role="alert"
        tabIndex={0}
        isInvalid={isInvalid}
      >
        {invalidMessage}
      </Styled.Error>
    </Styled.Container>
  );
};

export default Input;
