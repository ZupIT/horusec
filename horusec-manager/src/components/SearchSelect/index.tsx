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

import React, { InputHTMLAttributes, useEffect, useState } from 'react';
import isEmpty from 'lodash/isEmpty';
import { Field } from 'helpers/interfaces/Field';
import {
  FormControl,
  IconButton,
  InputAdornment,
  InputLabel,
  TextField,
  TextFieldProps,
} from '@material-ui/core';

import Visibility from '@material-ui/icons/Visibility';
import VisibilityOff from '@material-ui/icons/VisibilityOff';
import { getCurrentTheme } from 'helpers/localStorage/currentTheme';
import { useField, connect } from 'formik';
import { string } from 'yup';
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
}

function SelectInput({ label, name, options }: InputProps & TextFieldProps) {
  const { t } = useTranslation();
  const [field, { error, touched, value }] = useField(name);
  const [state, setState] = useState<Option>(
    options.find((el) => el.value === value)
  );

  useEffect(() => {
    state && field.onChange(name)(state.value);
  }, [state]);

  return (
    <div style={{ display: 'block' }}>
      <Autocomplete
        options={options}
        renderInput={(params) => (
          <TextField {...params} name={name} label={label} />
        )}
        openOnFocus
        getOptionLabel={(option) => option.label || ''}
        onChange={(event, value: any) => {
          setState(value);
        }}
        onBlur={field.onBlur}
        value={state}
        disableClearable
        disableListWrap
        noOptionsText={t('GENERAL.NO_OPTIONS')}
      />
    </div>
  );
}

export default connect(SelectInput);
