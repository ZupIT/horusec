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
import { Field } from 'helpers/interfaces/Field';
import {
  IconButton,
  InputAdornment,
  TextField,
  TextFieldProps,
} from '@material-ui/core';

import Visibility from '@material-ui/icons/Visibility';
import VisibilityOff from '@material-ui/icons/VisibilityOff';
import { getCurrentTheme } from 'helpers/localStorage/currentTheme';
import { useField, connect } from 'formik';
import { useTranslation } from 'react-i18next';
interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  ariaLabel?: string;
  name: string;
  invalidMessage?: string;
  width?: string;
  initialValue?: string;
  validation?: (value: string) => boolean;
  onChangeValue?: (params: Field) => any;
  multiline?: boolean;
}

function Input({
  label,
  ariaLabel,
  name,
  className,
  type,
  multiline = false,
  width = '100%',
  ...props
}: InputProps & TextFieldProps) {
  const [inputType, setInputType] = useState(type);
  const { t } = useTranslation();
  const theme = getCurrentTheme();
  const [field, { error, value }] = useField(name);

  return (
    <div style={{ display: 'block', width: width }} className={className}>
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
        aria-label={ariaLabel}
        aria-describedby={`${name}-error`}
        error={!!error}
        helperText={error}
        FormHelperTextProps={{
          tabIndex: 0,
          id: `${name}-error`,
          role: 'alert',
        }}
        autoComplete="off"
        InputProps={{
          endAdornment:
            type === 'password' ? (
              <InputAdornment position="end">
                <IconButton
                  aria-label={t('GENERAL.PASS_VISIBILITY')}
                  id={inputType === 'password' ? 'icon-view' : 'icon-no-view'}
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
