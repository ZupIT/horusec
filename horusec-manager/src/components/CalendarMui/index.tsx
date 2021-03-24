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
import { useTranslation } from 'react-i18next';
import useLanguage from 'helpers/hooks/useLanguage';
import { find } from 'lodash';
import { DatePicker, MuiPickersUtilsProvider } from '@material-ui/pickers';
import enLocale from 'date-fns/locale/en-US';
import ptBRLocale from 'date-fns/locale/pt-BR';
import format from 'date-fns/format';

import DateFnsUtils from '@date-io/date-fns';
import { connect, useField } from 'formik';

class PtBrLocalizedUtils extends DateFnsUtils {
  getCalendarHeaderText(date: number | Date) {
    return format(date, 'dd/MM/yyyy', { locale: this.locale });
  }

  getDatePickerHeaderText(date: number | Date) {
    return format(date, 'dd/MM/yyyy', { locale: this.locale });
  }
}

const localeUtilsMap = {
  enUS: DateFnsUtils,
  ptBR: PtBrLocalizedUtils,
};

const localeMap = {
  enUS: enLocale,
  ptBR: ptBRLocale,
};

interface CalendarProps {
  name: string;
  label: string;
  disabled?: boolean;
  minDate?: Date;
  maxDate?: Date;
}

type LocaleType = 'enUS' | 'ptBR';

function CalendarMui({
  name,
  label,
  disabled = false,
  minDate,
  maxDate,
}: CalendarProps) {
  const { i18n } = useTranslation();
  const [locale, setLocale] = useState<LocaleType>('enUS');
  const [dateFormat, setDateFormat] = useState('dd/MM/yyyy');
  const { allLanguages } = useLanguage();

  const [field, { error, touched, value }] = useField(name);

  useEffect(() => {
    const lang = find(allLanguages, { i18nValue: i18n.language });
    setDateFormat(lang.dateFormat);
    setLocale(lang.i18nValue as LocaleType);
  }, [i18n.language, allLanguages]);

  return (
    <MuiPickersUtilsProvider
      utils={localeUtilsMap[locale] || DateFnsUtils}
      locale={localeMap[locale]}
    >
      <DatePicker
        autoOk
        disableToolbar
        disabled={disabled}
        name={name}
        label={label}
        onBlur={field.onBlur(name)}
        onChange={(date) => field.onChange(name)(date.toString())}
        value={value}
        fullWidth
        format={dateFormat}
        error={touched && !!error}
        helperText={touched && error}
        id={name}
        maxDate={maxDate}
        minDate={minDate}
        variant="inline"
      />
    </MuiPickersUtilsProvider>
  );
}

export default connect(CalendarMui);
