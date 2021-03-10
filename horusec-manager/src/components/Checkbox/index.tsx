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

import React, { useState, useEffect } from 'react';
import Styled from './styled';

interface Props {
  initialValue: boolean;
  disabled: boolean;
  onChangeValue: (isChecked: boolean) => void;
  label?: string;
}

const Checkbox: React.FC<Props> = ({
  initialValue,
  disabled,
  onChangeValue,
  label,
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
    <Styled.Container>
      <Styled.Checkbox
        disabled={disabled}
        onClick={handleChangeValue}
        isChecked={isChecked}
      />
      {label ? (
        <Styled.Label onClick={handleChangeValue}>{label}</Styled.Label>
      ) : null}
    </Styled.Container>
  );
};

export default Checkbox;
