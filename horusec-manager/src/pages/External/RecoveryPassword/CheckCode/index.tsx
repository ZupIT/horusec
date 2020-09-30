import React, { FormEvent, useState, useEffect } from 'react';
import Styled from './styled';
import { useHistory } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import isEmptyString from 'helpers/validators/isEmptyString';
import { Field } from 'helpers/interfaces/Field';
import accountService from 'services/account';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import queryString from 'query-string';
import { isValidEmail } from 'helpers/validators';
import ExternalLayout from 'layouts/External';

function CheckCode() {
  const { t } = useTranslation();
  const history = useHistory();
  const { dispatchMessage } = useResponseMessage();

  const [code, setCode] = useState<Field>({ value: '', isValid: false });
  const [email, setEmail] = useState<Field>({ value: '', isValid: false });

  useEffect(() => {
    const params = queryString.parse(window.location.search);

    if (params?.email) {
      const value = params?.email as string;
      setEmail({ value, isValid: true });
    }

    if (params?.code) {
      const value = params?.code as string;
      setCode({ value, isValid: true });
    }
  }, []);

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (code.isValid) {
      accountService
        .validateCode(email.value, code.value)
        .then((result) => {
          const token = result?.data?.content;
          history.push(`/recovery-password/new-password?token=${token}`);
        })
        .catch((err) => {
          dispatchMessage(err?.response?.data);
        });
    }
  };

  return (
    <ExternalLayout>
      <>
        <Styled.SubTitle>{t('TYPE_THE_CODE')}</Styled.SubTitle>

        <Styled.Form onSubmit={handleSubmit}>
          <Styled.Field
            label={t('EMAIL')}
            name="email"
            type="text"
            onChangeValue={(value: Field) => setEmail(value)}
            invalidMessage={t('INVALID_EMAIL')}
            validation={isValidEmail}
            initialValue={email.value}
          />

          <Styled.Field
            label={t('CODE')}
            name="code"
            type="text"
            onChangeValue={(value: Field) => setCode(value)}
            invalidMessage={t('INVALID_CODE')}
            validation={isEmptyString}
            initialValue={code.value}
          />

          <Styled.Submit
            isDisabled={!code.isValid}
            text={t('CHECK_CODE')}
            type="submit"
            rounded
          />

          <Styled.BackToLogin
            onClick={() => history.push('/login')}
            text={t('BACK_LOGIN')}
            rounded
            outline
          />
        </Styled.Form>
      </>
    </ExternalLayout>
  );
}

export default CheckCode;
