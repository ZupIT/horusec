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

import React, { FormEvent, useState } from 'react';
import Styled from './styled';
import { useHistory } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Dialog } from 'components';
import emailValidator from 'helpers/validators/isValidEmail';
import { Field } from 'helpers/interfaces/Field';
import accountService from 'services/account';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import ExternalLayout from 'layouts/External';

function SendEmailScreen() {
  const { t } = useTranslation();
  const history = useHistory();
  const { dispatchMessage } = useResponseMessage();

  const [email, setEmail] = useState<Field>({ value: '', isValid: false });
  const [successDialogVisible, setSuccessDialogVisible] = useState(false);
  const [isLoading, setLoading] = useState(false);

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (email.isValid) {
      setLoading(true);

      accountService
        .sendCode(email.value)
        .then(() => {
          setSuccessDialogVisible(true);
        })
        .catch((err) => {
          dispatchMessage(err?.response?.data);
        })
        .finally(() => {
          setLoading(false);
        });
    }
  };

  return (
    <ExternalLayout>
      <>
        <Styled.SubTitle>
          {t('RECOVERY_PASS_SCREEN.INPUT_EMAIL')}
        </Styled.SubTitle>

        <Styled.Form onSubmit={handleSubmit}>
          <Styled.Field
            onChangeValue={(field: Field) => setEmail(field)}
            label={t('RECOVERY_PASS_SCREEN.EMAIL')}
            name="email"
            type="email"
            invalidMessage={t('RECOVERY_PASS_SCREEN.INVALID_EMAIL')}
            validation={emailValidator}
          />

          <Styled.Submit
            isLoading={isLoading}
            isDisabled={!email.isValid}
            text={t('RECOVERY_PASS_SCREEN.SUBMIT')}
            type="submit"
            rounded
          />

          <Styled.BackToLogin
            onClick={() => history.push('/login')}
            outline
            text={t('RECOVERY_PASS_SCREEN.BACK')}
            rounded
          />
        </Styled.Form>

        <Dialog
          isVisible={successDialogVisible}
          confirmText={t('RECOVERY_PASS_SCREEN.CONFIRM')}
          message={t('RECOVERY_PASS_SCREEN.SUCCESS')}
          onConfirm={() => history.push('/login')}
        />
      </>
    </ExternalLayout>
  );
}

export default SendEmailScreen;
