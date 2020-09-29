import React, { FormEvent, useState, useContext } from 'react';
import Styled from './styled';
import { useHistory } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Field } from 'helpers/interfaces/Field';
import { Dialog } from 'components';
import {
  isEmptyString,
  hasLowerCase,
  hasNumber,
  hasSpecialCharacter,
  hasUpperCase,
} from 'helpers/validators';
import { CreateAccountContext } from 'contexts/CreateAccount';

function PasswordForm() {
  const { t } = useTranslation();
  const history = useHistory();

  const {
    password,
    setPassword,
    confirmPass,
    setConfirmPass,
    isLoading,
    createAccount,
    successDialogVisible,
  } = useContext(CreateAccountContext);

  const [passValidations, setPassValidations] = useState({
    alpha: false,
    number: false,
    minCharacters: false,
    characterSpecial: false,
  });

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    createAccount();
  };

  const validateEqualsPassword = (value: string) => {
    return value === password.value;
  };

  const handlePasswordValue = (field: Field) => {
    setPassValidations({
      minCharacters: field.value.length < 8,
      alpha: !hasUpperCase(field.value) || !hasLowerCase(field.value),
      number: !hasNumber(field.value),
      characterSpecial: !hasSpecialCharacter(field.value),
    });

    setPassword(field);
  };

  return (
    <>
      <Styled.SubTitle>
        {t('CREATE_ACCOUNT_SCREEN.CREATE_NEW_PASS')}
      </Styled.SubTitle>

      <Styled.PassRequirements>
        <Styled.Info>
          {t('CREATE_ACCOUNT_SCREEN.PASSWORD_REQUIREMENTS')}
        </Styled.Info>

        <Styled.Item isInvalid={passValidations.minCharacters}>
          {t('CREATE_ACCOUNT_SCREEN.MIN_CHARACTERS')}
        </Styled.Item>

        <Styled.Item isInvalid={passValidations.alpha}>
          {t('CREATE_ACCOUNT_SCREEN.ALPHA_REQUIREMENTS')}
        </Styled.Item>

        <Styled.Item isInvalid={passValidations.number}>
          {t('CREATE_ACCOUNT_SCREEN.NUMBER_REQUIREMENT')}
        </Styled.Item>

        <Styled.Item isInvalid={passValidations.characterSpecial}>
          {t('CREATE_ACCOUNT_SCREEN.SPECIAL_CHARACTER')}
        </Styled.Item>

        <Styled.Info>{t('CREATE_ACCOUNT_SCREEN.NO_EQUALS')}</Styled.Info>

        <Styled.Item>{t('CREATE_ACCOUNT_SCREEN.USER_NAME')}</Styled.Item>
      </Styled.PassRequirements>

      <Styled.Form onSubmit={handleSubmit}>
        <Styled.Field
          onChangeValue={(field: Field) => handlePasswordValue(field)}
          label={t('CREATE_ACCOUNT_SCREEN.PASSWORD')}
          name="password"
          type="password"
          invalidMessage={t('CREATE_ACCOUNT_SCREEN.INVALID_PASS')}
          validation={isEmptyString}
        />

        <Styled.Field
          label={t('CREATE_ACCOUNT_SCREEN.CONFIRM_PASS')}
          onChangeValue={(field: Field) => setConfirmPass(field)}
          name="confirm-pass"
          type="password"
          invalidMessage={t('CREATE_ACCOUNT_SCREEN.INVALID_CONFIRM_PASS')}
          validation={validateEqualsPassword}
        />

        <Styled.Submit
          isDisabled={
            !confirmPass.isValid ||
            !password.isValid ||
            passValidations.alpha ||
            passValidations.characterSpecial ||
            passValidations.minCharacters ||
            passValidations.number
          }
          text={t('CREATE_ACCOUNT_SCREEN.SUBMIT')}
          type="submit"
          isLoading={isLoading}
          rounded
        />

        <Styled.BackToLogin
          onClick={() => history.push('/login')}
          text={t('CREATE_ACCOUNT_SCREEN.BACK')}
          outline
          rounded
        />
      </Styled.Form>

      <Dialog
        isVisible={successDialogVisible}
        confirmText={t('CREATE_ACCOUNT_SCREEN.CONFIRM')}
        message={t('CREATE_ACCOUNT_SCREEN.SUCCESS_CREATE_ACCOUNT')}
        onConfirm={() => history.push('/login')}
      />
    </>
  );
}

export default PasswordForm;
