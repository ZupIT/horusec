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


import { createStyles, makeStyles, Theme } from '@material-ui/core/styles';
import TextField from '@material-ui/core/TextField';

const useStyles = makeStyles({
  root: {
    background: 'linear-gradient(45deg, #FE6B8B 30%, #FF8E53 90%)',
    borderRadius: 3,
    border: 0,
    color: 'white',
    height: 48,
    padding: '0 30px',
    boxShadow: '0 3px 5px 2px rgba(255, 105, 135, .3)',
    // $disabled is a reference to the local disabled
    // rule within the same style sheet.
    // By using &, we increase the specificity.
    '&$disabled': {
      background: 'rgba(0, 0, 0, 0.12)',
      color: 'white',
      boxShadow: 'none',
    },
  },
  disabled: {},
});

type ModifiedField = Omit<Field, 'value'> & {
  value: Date;
};

interface CalendarProps {
  onChangeValue: (params: ModifiedField) => any;
  initialDate?: Date;
  title: string;
  disabled?: boolean;
  invalidMessage?: string;
  validation?: Function;
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

  const classes = useStyles();

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
      <TextField
        id="date"
        label="Birthday"
        type="date"
        className={classes.root}
        InputLabelProps={{
          shrink: true,
        }}
      />
    </Styled.Wrapper>
  );
};

export default Calendar;
