import React, { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import Styled from './styled';
import Icon from 'components/Icon';
import useLanguage from 'helpers/hooks/useLanguage';
import { find } from 'lodash';

interface CalendarProps {
  onChangeValue: (date: Date) => void;
  initialDate?: Date;
  title: string;
}

const Calendar: React.FC<CalendarProps> = ({
  onChangeValue,
  initialDate,
  title,
}) => {
  const [currentDate, setCurrentDate] = useState(null);
  const [dateFormat, setDateFormat] = useState('dd/MM/yyyy');
  const { i18n } = useTranslation();
  const { allLanguages } = useLanguage();

  const handleSelectedDate = (date: Date) => {
    setCurrentDate(date);
    onChangeValue(date);
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
          selected={currentDate}
          onChange={(date: Date) => handleSelectedDate(date)}
          dateFormat={dateFormat}
        />

        <Icon name="calendar" size="18px" />
      </Styled.Container>
    </Styled.Wrapper>
  );
};

export default Calendar;
