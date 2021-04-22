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

import React, { useState, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import Styled from './styled';
import Icon from 'components/Icon';
import useLanguage from 'helpers/hooks/useLanguage';
import { find } from 'lodash';
import ReactDatePicker, { ReactDatePickerProps } from 'react-datepicker';
import { Field } from 'helpers/interfaces/Field';

type ModifiedField = Omit<Field, 'value'> & {
  value: Date;
};

interface CalendarProps {
  onChangeValue: (params: ModifiedField) => any;
  initialDate?: Date;
  title: string;
  disabled?: boolean;
  invalidMessage?: string;
  validation?: (value: string) => boolean;
}

const Calendar: React.FC<
  CalendarProps & Omit<ReactDatePickerProps, 'onChange'>
> = (props) => {
  const {
    onChangeValue,
    initialDate,
    title,
    disabled,
    invalidMessage,
    validation,
  } = props;

  const [currentDate, setCurrentDate] = useState(null);
  const [dateFormat, setDateFormat] = useState('dd/MM/yyyy');
  const { i18n } = useTranslation();
  const { allLanguages } = useLanguage();
  const [isInvalid, setInvalid] = useState(false);

  const ref = useRef<ReactDatePicker>();

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
  }, [i18n.language, allLanguages]);

  useEffect(() => {
    setCurrentDate(initialDate ? initialDate : new Date());
  }, [initialDate]);

  return (
    <Styled.Wrapper>
      <Styled.Title>{title}</Styled.Title>

      <Styled.Container>
        <Styled.DatePicker
          ref={ref}
          disabled={disabled}
          selected={currentDate}
          onChange={(date: Date) => handleSelectedDate(date)}
          dateFormat={dateFormat}
          {...props}
        />

        <Icon
          name="calendar"
          size="18px"
          onClick={() => ref.current.setFocus()}
        />
      </Styled.Container>

      <Styled.Error isInvalid={isInvalid}>{invalidMessage}</Styled.Error>
    </Styled.Wrapper>
  );
};

export default Calendar;
