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
  onClick?: (event?: MouseEvent) => void;
  dataFor?: string;
  dataTip?: string;
  ariaLabel?: string;
  tabIndex?: number;
}

const Icon = React.forwardRef(
  (
    {
      name,
      color,
      size,
      className,
      onClick,
      isActive,
      title,
      dataTip,
      dataFor,
      ariaLabel,
      tabIndex,
    }: Props,
    ref: Ref<HTMLDivElement>
  ) => {
    const iRef = useRef<HTMLDivElement>(null);
    const [uri] = useDynamicImport(name);

    useImperativeHandle(ref, () => iRef.current);

    return (
      <Styled.Icon
        tabIndex={tabIndex}
        aria-label={ariaLabel}
        ref={iRef}
        data-testid={`icon-${name}`}
        className={className}
        color={isActive ? 'light' : color}
        size={size}
        onClick={onClick}
        onKeyPress={() => onClick()}
        title={title}
        data-tip={dataTip}
        data-for={dataFor}
      >
        {uri ? <ReactSVG src={uri} /> : ''}
      </Styled.Icon>
    );
  }
);

export default Icon;
