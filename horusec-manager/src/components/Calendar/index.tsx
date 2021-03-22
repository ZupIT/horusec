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
import { Field } from 'helpers/interfaces/Field';
import { DatePicker, MuiPickersUtilsProvider} from '@material-ui/pickers';
import enLocale from "date-fns/locale/en-US";
import ptBRLocale from "date-fns/locale/pt-BR";
import format from "date-fns/format";

import DateFnsUtils from "@date-io/date-fns";

type ModifiedField = Omit<Field, 'value'> & {
  value: Date;
};

class ptBrLocalizedUtils extends DateFnsUtils {
  getCalendarHeaderText(date: number | Date) {
    console.log('locale', this.locale);
    return format(date, "dd/MM/yyyy", { locale: this.locale });
  }

  getDatePickerHeaderText(date: number | Date) {
    return format(date, "dd/MM/yyyy", { locale: this.locale });
  }
}

const localeUtilsMap = {
    'enUS': DateFnsUtils,
    'ptBR': ptBrLocalizedUtils,
  };
  
const localeMap = {
  'enUS': enLocale,
  'ptBR': ptBRLocale,
};

interface CalendarProps {
  onChangeValue: (params: ModifiedField) => any;
  initialDate?: Date;
  title: string;
  disabled?: boolean;
  invalidMessage?: string;
  validation?: Function;
  minDate?: Date,
  maxDate?: Date,
}

type LocaleType = 'enUS' |'ptBR';

const Calendar: React.FC<CalendarProps> = (props) => {
  const {
    onChangeValue,
    initialDate,
    title,
    disabled,
    invalidMessage,
    validation,
  } = props;

  const [currentDate, setCurrentDate] = useState(null);
  const { i18n } = useTranslation();
  const [locale, setLocale] = useState<LocaleType>('enUS');
  const [dateFormat, setDateFormat] = useState('dd/MM/yyyy');
  const { allLanguages } = useLanguage();
  const [isInvalid, setInvalid] = useState(false);

  const handleSelectedDate = (date: Date) => {
    let isValid;
    if (validation) {
      isValid = validation(date.toDateString());

      setInvalid(!isValid);
    } else {
      isValid = true;
    }

    setCurrentDate(date);
    onChangeValue({ value: date, isValid });
  };

  useEffect(() => {
    const lang = find(allLanguages, { i18nValue: i18n.language });
    setDateFormat(lang.dateFormat);
    setLocale(lang.i18nValue as LocaleType)
  }, [i18n.language, allLanguages]);

  useEffect(() => {
    setCurrentDate(initialDate ? initialDate : new Date());
  }, [initialDate]);

  return (
    <MuiPickersUtilsProvider utils={localeUtilsMap[locale] || DateFnsUtils} locale={localeMap[locale]}>

      <DatePicker
        autoOk
        defaultValue={initialDate}
        disableToolbar
        disabled={disabled}
        error={isInvalid}
        format={dateFormat}
        helperText={invalidMessage}        
        id={`datepicker${title}`}
        label={title}
        maxDate={props.maxDate}
        minDate={props.minDate}
        onChange={handleSelectedDate}
        showTodayButton
        value={currentDate}
        variant="inline"
        />
        </MuiPickersUtilsProvider>
  );
};

export default Calendar;
