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

import React, { useContext } from 'react';
import Styled from './styled';
import { useHistory } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { CreateAccountContext } from 'contexts/CreateAccount';
import * as Yup from 'yup';
import { Formik } from 'formik';
interface UserInfoProps {
  onNextStep: () => void;
}

function UserInfoForm({ onNextStep }: UserInfoProps) {
  const { t } = useTranslation();
  const history = useHistory();
  const { isLoading, verifyUsernameAndEmail } = useContext(
    CreateAccountContext
  );

  const ValidationScheme = Yup.object({
    username: Yup.string().required(t('CREATE_ACCOUNT_SCREEN.INVALID_NAME')),
    email: Yup.string()
      .email(t('CREATE_ACCOUNT_SCREEN.INVALID_EMAIL'))
      .required(t('CREATE_ACCOUNT_SCREEN.INVALID_EMAIL')),
  });

  type InitialValue = Yup.InferType<typeof ValidationScheme>;

  const initialValues: InitialValue = {
    username: '',
    email: '',
  };

  return (
    <>
      <Styled.SubTitle>
        {t('CREATE_ACCOUNT_SCREEN.CREATE_ACCOUNT')}
      </Styled.SubTitle>
      <Formik
        initialValues={initialValues}
        validationSchema={ValidationScheme}
        onSubmit={(values) => {
          verifyUsernameAndEmail(values.email, values.username).then(() => {
            onNextStep();
          });
        }}
      >
        {(props) => (
          <Styled.Form>
            <Styled.Field
              label={t('CREATE_ACCOUNT_SCREEN.NAME')}
              ariaLabel={t('CREATE_ACCOUNT_SCREEN.ARIA_NAME')}
              name="username"
              type="username"
            />

            <Styled.Field
              label={t('CREATE_ACCOUNT_SCREEN.EMAIL')}
              ariaLabel={t('CREATE_ACCOUNT_SCREEN.ARIA_EMAIL')}
              name="email"
              type="text"
            />

            <Styled.Submit
              id="next-step"
              isDisabled={!props.isValid}
              text={t('CREATE_ACCOUNT_SCREEN.NEXT')}
              type="submit"
              isLoading={isLoading}
              rounded
            />

            <Styled.BackToLogin
              onClick={() => history.push('/auth')}
              text={t('CREATE_ACCOUNT_SCREEN.BACK')}
              outline
              rounded
            />
          </Styled.Form>
        )}
      </Formik>
    </>
  );
}

export default UserInfoForm;
