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
import { useTranslation } from 'react-i18next';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  text: string;
  outline?: boolean;
  rounded?: boolean;
  opaque?: boolean;
  isDisabled?: boolean;
  isLoading?: boolean;
  width?: number | string;
  height?: number;
  color?: string;
  icon?: string;
  disabledColor?: string;
  onClick?: (event: any) => any;
}

const Button: React.FC<ButtonProps> = ({
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
  onClick,
  ...props
}) => {
  const { t } = useTranslation();

  const handleClickEvent = (event: any) => {
    if (!isDisabled && onClick) onClick(event);
  };

  return (
    <Styled.Button
      {...props}
      isLoading={isLoading}
      outline={outline}
      rounded={rounded}
      opaque={opaque}
      aria-disabled={isDisabled || isLoading}
      isDisabled={isDisabled || isLoading}
      type={props.type || 'button'}
      width={width}
      height={height}
      color={color}
      disabledColor={disabledColor}
      onClick={handleClickEvent}
    >
      {isLoading ? (
        <Icon
          name="loading"
          size="35px"
          ariaLabel={t('GENERAL.BUTTON_LOADING')}
        />
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

export default Button;
