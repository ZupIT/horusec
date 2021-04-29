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

import React, { memo, useEffect, useState } from 'react';
import isEmpty from 'lodash/isEmpty';
import { TextField, TextFieldProps } from '@material-ui/core';
import { useField, connect } from 'formik';
import { Autocomplete } from '@material-ui/lab';
import { useTranslation } from 'react-i18next';
interface Option {
  label: string;
  value: any;
}
interface InputProps {
  label: string;
  name: string;
  options: Option[];
  width?: string;
}

function SelectInput({
  label,
  name,
  options,
  width = '100%',
}: InputProps & TextFieldProps) {
  const { t } = useTranslation();
  const [field, { error, touched, initialValue }, { setValue }] = useField(
    name
  );
  const getOption = options.find((el) => el.value === initialValue) || null;

  const [state, setState] = useState<Option | null>(getOption);

  useEffect(() => {
    if (isEmpty(state) && options.length && initialValue) {
      setState(getOption);
    }
  }, [initialValue, getOption, state, options.length]);

  return (
    <div style={{ display: 'block', width: width }}>
      <Autocomplete
        id={`select-${name}`}
        options={options}
        getOptionLabel={(option) => option.label || ''}
        getOptionSelected={(option, value) => {
          return value !== undefined ? option.value === value.value : false;
        }}
        value={state}
        onChange={(_event, value: any) => {
          setState(value);
          setValue(value ? value.value : '');
        }}
        onBlur={field.onBlur}
        renderInput={(params) => (
          <TextField
            {...params}
            name={name}
            label={label}
            size="small"
            error={touched && !!error}
            helperText={touched && error}
            FormHelperTextProps={{ tabIndex: 0 }}
          />
        )}
        disableClearable
        noOptionsText={t('GENERAL.NO_OPTIONS')}
      />
    </div>
  );
}

export default connect(memo(SelectInput));
