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
