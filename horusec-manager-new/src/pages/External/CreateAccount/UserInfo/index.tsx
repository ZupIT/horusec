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
