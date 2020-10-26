import React from 'react';
import {Button} from './button-styled';

export default ({href, target, ref, children}) => {
  return (
    <Button href={href} target={target} ref={ref}>{children}</Button>
  );
};
