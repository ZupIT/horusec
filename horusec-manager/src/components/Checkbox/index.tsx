import React, { useState, useEffect } from 'react';
import Styled from './styled';

interface Props {
  initialValue: boolean;
  disabled: boolean;
  onChangeValue: (isChecked: boolean) => void;
}

const Checkbox: React.FC<Props> = ({
  initialValue,
  disabled,
  onChangeValue,
}) => {
  const [isChecked, setChecked] = useState(false);

  const handleChangeValue = () => {
    if (!disabled) {
      setChecked(!isChecked);
      onChangeValue(!isChecked);
    }
  };

  useEffect(() => {
    setChecked(initialValue);
  }, [initialValue]);

  return (
    <Styled.Checkbox
      disabled={disabled}
      onClick={handleChangeValue}
      isChecked={isChecked}
    />
  );
};

export default Checkbox;
