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

import React, {
  useState,
  useEffect,
  CSSProperties,
} from "react";
import Styled from "./styled";
import { useTranslation } from "react-i18next";
import { get, isObject, isString } from "lodash";
import { ObjectLiteral } from "helpers/interfaces/ObjectLiteral";

import Select, { OptionType, StylesConfig } from "@atlaskit/select";
import { useTheme } from "styled-components";

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
  width?: string;
  selectText?: string;
  background?: string;
  backgroundColor?: {
    colors: ObjectLiteral;
    default: string;
  };
  hasSearch?: boolean;
  appearance?: "default" | "underline";
}

const SelectInput: React.FC<Props> = ({
  title,
  options,
  onChangeValue,
  className,
  initialValue,
  keyLabel = "label",
  keyValue = "value",
  appearance = "default",
  width,
  selectText,
  fixedItemTitle,
  onClickFixedItem,
  background,
  backgroundColor,
  disabled = false,
  hasSearch = false,
}) => {
  const [currentValue, setCurrentValue] = useState<OptionType>(null);
  const { t } = useTranslation();
  const theme = useTheme();

  background = background || theme.colors.select.background;

  const selectOptions: OptionType[] = options.map((option) => ({
    label: option[keyLabel],
    value: keyValue ? option[keyValue] || option[keyLabel]: null ,
    option: option,
  }));
  
  if (fixedItemTitle) {
    selectOptions.push({
      label: fixedItemTitle,
      value: fixedItemTitle,
      option: fixedItemTitle
    });
  }

  const handleSelectedValue = (option: any) => {

    if (fixedItemTitle && option.option === fixedItemTitle) {
      onClickFixedItem()
    } else if (!disabled) {
      onChangeValue(option.option);
      setCurrentValue(option);
    }
  };

  const getValue = (currentOption: string | number) => {
    return selectOptions.find((value) => value.value === currentOption) || null;
  };

  useEffect(() => {
    if (initialValue) {
      setCurrentValue(() => {

        if (isObject(initialValue)) {
          return getValue(initialValue[keyLabel]) || getValue(initialValue[keyValue]);
        }

        if (isString(initialValue)) {
          return getValue(initialValue);
        }

        return null;
      });
    }
    // eslint-disable-next-line
  }, [initialValue]);

  const controlBackground = (() => {
    if (backgroundColor && currentValue) {
      const { colors, default: colorDefault } = backgroundColor;
      return get(colors, currentValue.value, colorDefault);
    }
    return background;
  })();

  const selectStyles: Partial<StylesConfig<OptionType, false>> = {
    control: (style: CSSProperties) => {
      const styles = {
        ...style,
        background: controlBackground,
        minHeight: "auto",
        border: "none",
        borderRadius: 4,
        ":hover": {
          background: controlBackground,
          borderColor: "#fff",
        },
      };

      if (appearance === "underline") {
        styles["borderBottom"] = "1px solid #fff";
        styles["borderRadius"] = 0;
      }

      return styles;
    },
    placeholder: (style: CSSProperties) => ({
      ...style,
      color: theme.colors.select.text,
    }),
    dropdownIndicator: (style: CSSProperties) => ({
      ...style,
      color: theme.colors.select.text,
    }),
    menuList: (style: CSSProperties) => ({
      ...style,
      background: theme.colors.background.highlight,
    }),
    input: (style: CSSProperties) => ({
      ...style,
      color: theme.colors.select.text,
      fontSize: theme.metrics.fontSize.medium,
    }),
    option: (style: CSSProperties) => {

      const styles = {
        ...style,
        color: theme.colors.select.text,
        fontSize: theme.metrics.fontSize.small,
        background: theme.colors.background.highlight,
        ":hover": {
          background: theme.colors.background.primary,
        },
        ":last-child" : {},
      };

      if (fixedItemTitle) {
        styles[":last-child"] = {
          color: theme.colors.select.highlight,
          textDecoration: 'underline',
        };
      }

      return styles;
    },
    singleValue: (style: CSSProperties) => ({
      ...style,
      color: theme.colors.select.text,
      fontSize: theme.metrics.fontSize.medium,
    }),
  };

  return (
    <Styled.Container width={width}>
      {title ? <Styled.Title>{title}</Styled.Title> : null}
      <Select
        value={getValue(currentValue?.value)}
        className={className}
        isSearchable={hasSearch}
        isDisabled={disabled}
        styles={selectStyles}
        options={selectOptions}
        onChange={(option) => handleSelectedValue(option)}
        placeholder={selectText || t("GENERAL.SELECT") + "..."}
        noOptionsMessage={() => t("GENERAL.NO_OPTIONS")}
      />
    </Styled.Container>
    // <Styled.Wrapper
    //   rounded={rounded}
    //   disabled={disabled}
    //   width={width}
    //   onClick={() => (disabled ? null : setOpenOptionsList(!openOptionsList))}
    // >
    //   {title ? <Styled.Title>{title}</Styled.Title> : null}

    //   <Styled.Container
    //     disabled={disabled}
    //     rounded={rounded}
    //     className={className}
    //     width={width}
    //     backgroundColor={
    //       backgroundColors
    //         ? get(
    //             backgroundColors.colors,
    //             currentValue,
    //             backgroundColors.default
    //           )
    //         : null
    //     }
    //   >
    //     <Styled.CurrentValue
    //       disabled={!hasSearch}
    //       type="text"
    //       onChange={handleSearchValue}
    //       value={currentValue}
    //     />

    //     <Styled.OptionsList
    //       isOpen={openOptionsList}
    //       rounded={rounded}
    //       width={width}
    //       height={optionsHeight}
    //       className="options-list"
    //       ref={optionsRef}
    //     >
    //       {filteredOptions.map((option, index) => (
    //         <Styled.OptionItem
    //           rounded={rounded}
    //           key={index}
    //           className="options-item"
    //           onClick={() => handleSelectedValue(option)}
    //         >
    //           {option[keyLabel]}
    //         </Styled.OptionItem>
    //       ))}

    //       {fixedItemTitle ? (
    //         <Styled.FixedOptionItem
    //           rounded={rounded}
    //           onClick={onClickFixedItem}
    //         >
    //           {fixedItemTitle}
    //         </Styled.FixedOptionItem>
    //       ) : null}
    //     </Styled.OptionsList>

    //     <Icon name="down" size="12px" />
    //   </Styled.Container>
    // </Styled.Wrapper>
  );
};

export default SelectInput;
