import React, { useState, useEffect, MouseEvent } from 'react';
import { useTranslation } from 'react-i18next';
import Styled from './styled';
import Button from '../Button';
import { useTheme } from 'styled-components';

interface DialogProps {
  message: string;
  hasCancel?: boolean;
  isVisible: boolean;
  onConfirm: Function;
  onCancel?: Function;
  confirmText: string;
  defaultButton?: boolean;
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
}) => {
  const [visibility, setVisibility] = useState(false);
  const { t } = useTranslation();
  const { colors } = useTheme();

  useEffect(() => {
    setVisibility(isVisible);
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
            <Styled.Message>{message}</Styled.Message>

            <Styled.Content>{children}</Styled.Content>

            <Styled.ButtonsWrapper>
              {hasCancel ? (
                <Button
                  text={t('GENERAL.CANCEL')}
                  width={105}
                  height={35}
                  rounded={!defaultButton}
                  outline
                  onClick={() => onCancel()}
                />
              ) : null}

              <Button
                text={confirmText}
                width={105}
                height={35}
                onClick={(e) => handleConfirm(e)}
                rounded={!defaultButton}
                color={defaultButton ? colors.dialog.confirmBtn : null}
                disabledColor={disabledColor}
                isDisabled={disableConfirm}
                isLoading={loadingConfirm}
              />
            </Styled.ButtonsWrapper>
          </Styled.Wrapper>
        </Styled.Background>
      ) : null}
    </>
  );
};

export default Dialog;
