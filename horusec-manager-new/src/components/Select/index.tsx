import React, { useState, useEffect } from 'react';
import Icon from 'components/Icon';
import Styled from './styled';
import { useTranslation } from 'react-i18next';

interface Props {
  title?: string;
  options: any[];
  disabled?: boolean;
  keyLabel: string;
  onChangeValue: (value: any) => any;
  className?: string;
  initialValue?: any;
  keyValue?: string;
  rounded?: boolean;
  width?: string;
}

const Select: React.FC<Props> = ({
  title,
  keyLabel,
  options,
  onChangeValue,
  className,
  disabled,
  initialValue,
  keyValue,
  rounded,
  width,
}) => {
  const [currentValue, setCurrentValue] = useState<any>(null);
  const [openOptionsList, setOpenOptionsList] = useState(false);
  const { t } = useTranslation();

  const handleSelectedValue = (option: any) => {
    if (!disabled) {
      setCurrentValue(option);
      onChangeValue(option);
    }
  };

  useEffect(() => {
    if (options && options.length > 0) {
      if (initialValue) {
        setCurrentValue(
          options.filter((item) => item[keyValue] === initialValue)[0]
        );
      } else {
        setCurrentValue(options[0]);
      }
    }

    // eslint-disable-next-line
  }, [initialValue, keyValue]);

  return (
    <Styled.Wrapper
      rounded={rounded}
      disabled={disabled}
      width={width}
      onClick={() => (disabled ? null : setOpenOptionsList(!openOptionsList))}
    >
      {title ? <Styled.Title>{title}</Styled.Title> : null}

      <Styled.Container
        disabled={disabled}
        rounded={rounded}
        className={className}
        width={width}
      >
        <Styled.CurrentValue>
          {currentValue ? currentValue[keyLabel] : t('SELECT')}
        </Styled.CurrentValue>

        <Styled.OptionsList
          isOpen={openOptionsList}
          rounded={rounded}
          width={width}
        >
          {options.map((option, index) => (
            <Styled.OptionItem
              rounded={rounded}
              key={index}
              onClick={() => handleSelectedValue(option)}
            >
              {option[keyLabel]}
            </Styled.OptionItem>
          ))}
        </Styled.OptionsList>

        <Icon name="down" size="12px" />
      </Styled.Container>
    </Styled.Wrapper>
  );
};

export default Select;
