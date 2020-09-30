import React, { useState, FormEvent } from 'react';
import Styled from './styled';
import { isValidEmail, isEmptyString } from 'helpers/validators';
import { useHistory } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Field } from 'helpers/interfaces/Field';
import useAuth from 'helpers/hooks/useAuth';
import ExternalLayout from 'layouts/External';

function LoginScreen() {
  const { t } = useTranslation();
  const history = useHistory();
  const { login, loginInProgress } = useAuth();

  const [email, setEmail] = useState<Field>({ value: '', isValid: false });
  const [password, setPassword] = useState<Field>({
    value: '',
    isValid: false,
  });

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (email.isValid && password.isValid) {
      login(email.value, password.value).then(() =>
        history.push('/organization')
      );
    }
  };

  return (
    <ExternalLayout>
      <Styled.Form onSubmit={handleSubmit}>
        <Styled.Field
          label={t('LOGIN_SCREEN.EMAIL')}
          name="email"
          type="text"
          onChangeValue={(field: Field) => setEmail(field)}
          invalidMessage={t('LOGIN_SCREEN.INVALID_EMAIL')}
          validation={isValidEmail}
        />

        <Styled.Field
          label={t('LOGIN_SCREEN.PASSWORD')}
          name="password"
          type="password"
          onChangeValue={(field: Field) => setPassword(field)}
          validation={isEmptyString}
          invalidMessage={t('LOGIN_SCREEN.INVALID_PASS')}
        />

        <Styled.ForgotPass onClick={() => history.push('/recovery-password')}>
          {t('LOGIN_SCREEN.FORGOT_PASS')}
        </Styled.ForgotPass>

        <Styled.Submit
          isDisabled={!password.isValid || !email.isValid}
          isLoading={loginInProgress}
          text={t('LOGIN_SCREEN.SUBMIT')}
          type="submit"
          rounded
        />

        <Styled.Register
          onClick={() => history.push('/create-account')}
          outline
          text={t('LOGIN_SCREEN.NO_ACCOUNT')}
          rounded
        />
      </Styled.Form>
    </ExternalLayout>
  );
}

export default LoginScreen;
