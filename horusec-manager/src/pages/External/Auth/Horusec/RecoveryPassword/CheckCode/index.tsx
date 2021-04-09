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
          history.push(`/auth/recovery-password/new-password?token=${token}`);
        })
        .catch((err) => {
          dispatchMessage(err?.response?.data);
        });
    }
  };

  return (
    <Styled.Container>
      <Styled.SubTitle>
        {t('RECOVERY_PASS_SCREEN.TYPE_THE_CODE')}
      </Styled.SubTitle>

      <Styled.Form onSubmit={handleSubmit}>
        <Styled.Field
          label={t('RECOVERY_PASS_SCREEN.EMAIL')}
          ariaLabel={t('RECOVERY_PASS_SCREEN.ARIA_INPUT_EMAIL')}
          name="email"
          type="text"
          onChangeValue={(value: Field) => setEmail(value)}
          invalidMessage={t('RECOVERY_PASS_SCREEN.INVALID_EMAIL')}
          validation={isValidEmail}
          initialValue={email.value}
        />

        <Styled.Field
          label={t('RECOVERY_PASS_SCREEN.CODE')}
          ariaLabel={t('RECOVERY_PASS_SCREEN.ARIA_CODE')}
          name="code"
          type="text"
          onChangeValue={(value: Field) => setCode(value)}
          invalidMessage={t('RECOVERY_PASS_SCREEN.INVALID_CODE')}
          validation={isEmptyString}
          initialValue={code.value}
        />

        <Styled.Submit
          isDisabled={!code.isValid}
          text={t('RECOVERY_PASS_SCREEN.CHECK_CODE')}
          type="submit"
          onClick={handleSubmit}
          rounded
        />

        <Styled.BackToLogin
          onClick={() => history.push('/auth')}
          text={t('RECOVERY_PASS_SCREEN.BACK')}
          rounded
          outline
        />
      </Styled.Form>
    </Styled.Container>
  );
}

export default CheckCode;
