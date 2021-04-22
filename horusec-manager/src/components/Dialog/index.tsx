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

import React, { useState, useEffect, MouseEvent } from 'react';
import { useTranslation } from 'react-i18next';
import Styled from './styled';
import Button from '../Button';
import { useTheme } from 'styled-components';

interface DialogProps {
  message: string;
  hasCancel?: boolean;
  isVisible: boolean;
  onConfirm: () => void;
  onCancel?: () => void;
  confirmText: string;
  defaultButton?: boolean;
  roundedButton?: boolean;
  width?: number;
  disableConfirm?: boolean;
  disabledColor?: string;
  loadingConfirm?: boolean;
}

const Dialog: React.FC<DialogProps> = ({
  message,
  hasCancel,
  isVisible,
  onConfirm,
  onCancel,
  confirmText,
  defaultButton,
  children,
  width,
  disableConfirm,
  disabledColor,
  loadingConfirm,
  roundedButton,
}) => {
  const [visibility, setVisibility] = useState(false);
  const { t } = useTranslation();
  const { colors } = useTheme();

  useEffect(() => {
    setVisibility(isVisible);
    setTimeout(() => {
      const message = document.getElementById('message-dialog');
      if (message) message.click();
    }, 600);
  }, [isVisible]);

  const handleConfirm = (event: MouseEvent<HTMLButtonElement>) => {
    event.preventDefault();
    onConfirm();
  };

  return (
    <>
      {visibility ? (
        <Styled.Background>
          <Styled.Wrapper width={width}>
            <Styled.Message id="message-dialog">{message}</Styled.Message>

            <Styled.Content>{children}</Styled.Content>

            <Styled.ButtonsWrapper>
              {hasCancel ? (
                <Button
                  text={t('GENERAL.CANCEL')}
                  width={120}
                  height={35}
                  rounded={roundedButton}
                  outline
                  onClick={() => onCancel()}
                  tabIndex={0}
                />
              ) : null}

              <Button
                text={confirmText}
                width={120}
                height={35}
                onClick={(e) => handleConfirm(e)}
                rounded={roundedButton}
                color={defaultButton ? colors.dialog.confirmBtn : null}
                disabledColor={disabledColor}
                isDisabled={disableConfirm}
                isLoading={loadingConfirm}
                tabIndex={0}
              />
            </Styled.ButtonsWrapper>
          </Styled.Wrapper>
        </Styled.Background>
      ) : null}
    </>
  );
};

export default Dialog;
