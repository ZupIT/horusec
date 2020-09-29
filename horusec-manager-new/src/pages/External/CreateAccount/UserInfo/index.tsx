import React, { FormEvent, useContext } from 'react';
import Styled from './styled';
import { useHistory } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { isEmptyString, isValidEmail } from 'helpers/validators';
import { Field } from 'helpers/interfaces/Field';
import { CreateAccountContext } from 'contexts/CreateAccount';

interface UserInfoProps {
  onNextStep: Function;
}

function UserInfoForm({ onNextStep }: UserInfoProps) {
  const { t } = useTranslation();
  const history = useHistory();
  const { email, setEmail, username, setUsername } = useContext(
    CreateAccountContext
  );

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (email.isValid && username.isValid) {
      onNextStep();
    }
  };

  return (
    <>
      <Styled.SubTitle>{t('CREATE_ACCOUNT')}</Styled.SubTitle>

      <Styled.Form onSubmit={handleSubmit}>
        <Styled.Field
          onChangeValue={(field: Field) => setUsername(field)}
          label={t('NAME')}
          name="username"
          type="username"
          invalidMessage={t('INVALID_NAME')}
          validation={isEmptyString}
        />

        <Styled.Field
          label={t('EMAIL')}
          onChangeValue={(field: Field) => setEmail(field)}
          name="email"
          type="text"
          invalidMessage={t('INVALID_EMAIL')}
          validation={isValidEmail}
        />

        <Styled.Submit
          isDisabled={!email.isValid || !username.isValid}
          text={t('NEXT')}
          type="submit"
          rounded
        />

        <Styled.BackToLogin
          onClick={() => history.push('/login')}
          text={t('BACK_LOGIN')}
          outline
          rounded
        />
      </Styled.Form>
    </>
  );
}

export default UserInfoForm;
