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

import React, { CSSProperties } from 'react';
import { useTranslation } from 'react-i18next';
import { FormControl, InputLabel, MenuItem, Select } from '@material-ui/core';
import { ObjectLiteral } from 'helpers/interfaces/ObjectLiteral';

interface Props {
  label?: string;
  value: any;
  options: { label: string; value: any }[];
  disabled?: boolean;
  onChangeValue: (value: any) => any;
  className?: string;
  width?: string;
  optionsHeight?: string;
  selectText?: string;
  backgroundColors?: {
    colors: ObjectLiteral;
    default: string;
  };
  hasSearch?: boolean;
  ariaLabel?: string;
  testId?: string;
  placeholder?: string;
  style?: CSSProperties;
}

const SelectInput: React.FC<Props> = ({
  label,
  options,
  onChangeValue,
  className,
  value,
  width = '100%',
  disabled = false,
  placeholder,
  style,
}) => {
  const { t } = useTranslation();

  return (
    <FormControl className={className} style={{ width: width }}>
      {label && <InputLabel id="select-label">{label}</InputLabel>}
      <Select
        labelId="select-label"
        id="select"
        disabled={disabled}
        value={value}
        onChange={({ target }) => {
          onChangeValue(target.value);
        }}
        placeholder={placeholder || t('GENERAL.SELECT') + '...'}
        style={style}
      >
        {options.map((el, index) => (
          <MenuItem key={index} value={el.value}>
            {el.label}
          </MenuItem>
        ))}
      </Select>
    </FormControl>
  );
};

export default SelectInput;
