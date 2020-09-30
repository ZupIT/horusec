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

import React, { ButtonHTMLAttributes } from 'react';
import Styled from './styled';
import { Icon } from 'components';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  text: string;
  outline?: boolean;
  rounded?: boolean;
  opaque?: boolean;
  isDisabled?: boolean;
  isLoading?: boolean;
  width?: number;
  height?: number;
  color?: string;
  icon?: string;
  disabledColor?: string;
}

const RoundButton: React.FC<ButtonProps> = ({
  text,
  outline,
  rounded,
  opaque,
  isDisabled,
  isLoading,
  width,
  height,
  color,
  icon,
  disabledColor,
  ...props
}) => {
  return (
    <Styled.Button
      {...props}
      isLoading={isLoading}
      outline={outline}
      rounded={rounded}
      opaque={opaque}
      disabled={isDisabled || isLoading}
      type={props.type || 'button'}
      width={width}
      height={height}
      color={color}
      disabledColor={disabledColor}
    >
      {isLoading ? (
        <Icon name="loading" size="35px" />
      ) : (
        <>
          {icon ? (
            <Styled.IconWrapper>
              <Icon name={icon} size="14px" />
            </Styled.IconWrapper>
          ) : null}
          <Styled.Label>{text}</Styled.Label>
        </>
      )}
    </Styled.Button>
  );
};

export default RoundButton;
