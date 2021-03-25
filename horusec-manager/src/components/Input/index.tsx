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

import React, { InputHTMLAttributes, useState } from 'react';
import isEmpty from 'lodash/isEmpty';
import { Field } from 'helpers/interfaces/Field';
import {
  FormControl,
  FormControlLabel,
  IconButton,
  InputAdornment,
  TextField,
  TextFieldProps,
} from '@material-ui/core';

import Visibility from '@material-ui/icons/Visibility';
import VisibilityOff from '@material-ui/icons/VisibilityOff';
import { getCurrentTheme } from 'helpers/localStorage/currentTheme';
import { useField, connect } from 'formik';
interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  name: string;
  invalidMessage?: string;
  width?: string;
  initialValue?: string;
  validation?: Function;
  onChangeValue?: (params: Field) => any;
  multiline?: boolean;
}

function Input({
  label,
  name,
  className,
  type,
  multiline = false,
  ...props
}: InputProps & TextFieldProps) {
  const [inputType, setInputType] = useState(type);
  const theme = getCurrentTheme();
  const [field, { error, touched, value }] = useField(name);

  return (
    <div style={{ display: 'block' }} className={className}>
      <TextField
        id={name}
        name={name}
        label={label}
        type={inputType}
        onBlur={field.onBlur(name)}
        onChange={field.onChange(name)}
        value={value}
        fullWidth
        multiline={multiline}
        error={touched && !!error}
        helperText={touched && error}
        FormHelperTextProps={{
          tabIndex: 0,
        }}
        autoComplete="off"
        InputProps={{
          endAdornment:
            type === 'password' ? (
              <InputAdornment position="end">
                <IconButton
                  aria-label="toggle password visibility"
                  onClick={() =>
                    inputType === 'password'
                      ? setInputType('text')
                      : setInputType('password')
                  }
                  style={{
                    color: theme.colors.input.label,
                  }}
                >
                  {inputType === 'password' ? (
                    <Visibility />
                  ) : (
                    <VisibilityOff />
                  )}
                </IconButton>
              </InputAdornment>
            ) : null,
        }}
        {...props}
      />
    </div>
  );
}

export default connect(Input);
