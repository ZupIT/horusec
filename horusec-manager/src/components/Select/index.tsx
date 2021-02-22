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

import React, { useState, useEffect, useRef, ChangeEvent } from 'react';
import Icon from 'components/Icon';
import Styled from './styled';
import { useTranslation } from 'react-i18next';
import { isObject, isString } from 'lodash';
import useOutsideClick from 'helpers/hooks/useClickOutside';
import { ObjectLiteral } from 'helpers/interfaces/ObjectLiteral';

interface Props {
  title?: string;
  options: any[];
  disabled?: boolean;
  fixedItemTitle?: string;
  onClickFixedItem?: () => void;
  keyLabel: string;
  onChangeValue: (value: any) => any;
  className?: string;
  initialValue?: ObjectLiteral | string;
  keyValue?: string;
  rounded?: boolean;
  width?: string;
  optionsHeight?: string;
  selectText?: string;
  hasSearch?: boolean;
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
  optionsHeight,
  selectText,
  fixedItemTitle,
  onClickFixedItem,
  hasSearch,
}) => {
  const [currentValue, setCurrentValue] = useState<string>('');
  const [filteredOptions, setFilteredOptions] = useState<any[]>(options);
  const [openOptionsList, setOpenOptionsList] = useState(false);
  const { t } = useTranslation();

  const optionsRef = useRef<HTMLDivElement>();

  useOutsideClick(optionsRef, () => {
    if (openOptionsList) setOpenOptionsList(false);
  });

  const handleSelectedValue = (option: any) => {
    if (!disabled) {
      onChangeValue(option);
      setCurrentValue(option[keyLabel]);
      setFilteredOptions(options);
    }
  };

  const renderSelectText = () => {
    setCurrentValue(selectText || t('GENERAL.SELECT'));
  };

  const handleSearchValue = (event: ChangeEvent<HTMLInputElement>) => {
    event.preventDefault();
    const { value } = event.target;
    setCurrentValue(value);

    const filteredItens = options.filter((item) =>
      item[keyLabel].toLowerCase().includes(value.toLowerCase())
    );

    setFilteredOptions(filteredItens);
  };

  useEffect(() => {
    setFilteredOptions(options);

    if (!initialValue) renderSelectText();

    if (isObject(initialValue)) {
      setCurrentValue(initialValue[keyLabel]);
    } else if (isString(initialValue)) {
      setCurrentValue(
        options.filter((item) => item[keyValue] === initialValue)[0]
      );
    }
    // eslint-disable-next-line
  }, [initialValue]);

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
        <Styled.CurrentValue
          disabled={!hasSearch}
          type="text"
          onChange={handleSearchValue}
          value={currentValue}
        />

        <Styled.OptionsList
          isOpen={openOptionsList}
          rounded={rounded}
          width={width}
          height={optionsHeight}
          className="options-list"
          ref={optionsRef}
        >
          {filteredOptions.map((option, index) => (
            <Styled.OptionItem
              rounded={rounded}
              key={index}
              className="options-item"
              onClick={() => handleSelectedValue(option)}
            >
              {option[keyLabel]}
            </Styled.OptionItem>
          ))}

          {fixedItemTitle ? (
            <Styled.FixedOptionItem
              rounded={rounded}
              onClick={onClickFixedItem}
            >
              {fixedItemTitle}
            </Styled.FixedOptionItem>
          ) : null}
        </Styled.OptionsList>

        <Icon name="down" size="12px" />
      </Styled.Container>
    </Styled.Wrapper>
  );
};

export default Select;
