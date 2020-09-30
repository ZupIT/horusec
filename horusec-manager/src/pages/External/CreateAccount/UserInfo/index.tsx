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
      <Styled.SubTitle>
        {t('CREATE_ACCOUNT_SCREEN.CREATE_ACCOUNT')}
      </Styled.SubTitle>

      <Styled.Form onSubmit={handleSubmit}>
        <Styled.Field
          onChangeValue={(field: Field) => setUsername(field)}
          label={t('CREATE_ACCOUNT_SCREEN.NAME')}
          name="username"
          type="username"
          invalidMessage={t('CREATE_ACCOUNT_SCREEN.INVALID_NAME')}
          validation={isEmptyString}
        />

        <Styled.Field
          label={t('CREATE_ACCOUNT_SCREEN.EMAIL')}
          onChangeValue={(field: Field) => setEmail(field)}
          name="email"
          type="text"
          invalidMessage={t('CREATE_ACCOUNT_SCREEN.INVALID_EMAIL')}
          validation={isValidEmail}
        />

        <Styled.Submit
          isDisabled={!email.isValid || !username.isValid}
          text={t('CREATE_ACCOUNT_SCREEN.NEXT')}
          type="submit"
          rounded
        />

        <Styled.BackToLogin
          onClick={() => history.push('/login')}
          text={t('CREATE_ACCOUNT_SCREEN.BACK')}
          outline
          rounded
        />
      </Styled.Form>
    </>
  );
}

export default UserInfoForm;
