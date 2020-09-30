import React, { Ref, useRef, useImperativeHandle, MouseEvent } from 'react';
import { ReactSVG } from 'react-svg';
import useDynamicImport from 'helpers/hooks/useDynamicImport';
import Styled from './styled';

export interface Props {
  name: string;
  size?: string;
  color?: string;
  title?: string;
  className?: string;
  isActive?: boolean;
  onClick?: (event: MouseEvent) => void;
}

const Icon = React.forwardRef(
  (
    { name, color, size, className, onClick, isActive, title }: Props,
    ref: Ref<HTMLDivElement>
  ) => {
    const iRef = useRef<HTMLDivElement>(null);
    const [uri] = useDynamicImport(name);

    useImperativeHandle(ref, () => iRef.current);

    return (
      <Styled.Icon
        ref={iRef}
        data-testid={`icon-${name}`}
        className={className}
        color={isActive ? 'light' : color}
        size={size}
        onClick={onClick}
        title={title}
      >
        {uri ? <ReactSVG src={uri} /> : ''}
      </Styled.Icon>
    );
  }
);

export default Icon;
