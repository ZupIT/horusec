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

import React, { useState } from "react";
import Styled from "./styled";
import { useHistory } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { Dialog } from "components";
import accountService from "services/account";
import useResponseMessage from "helpers/hooks/useResponseMessage";
import * as Yup from "yup";
import { Formik } from "formik";

function SendEmailScreen() {
  const { t } = useTranslation();
  const history = useHistory();
  const { dispatchMessage } = useResponseMessage();

  const [successDialogVisible, setSuccessDialogVisible] = useState(false);
  const [isLoading, setLoading] = useState(false);

  const handleSubmit = (email: string) => {
    setLoading(true);

    accountService
      .sendCode(email)
      .then(() => {
        setSuccessDialogVisible(true);
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      })
      .finally(() => {
        setLoading(false);
      });
  };

  const ValidationScheme = Yup.object({
    email: Yup.string()
      .email(t("RECOVERY_PASS_SCREEN.INVALID_EMAIL"))
      .required(),
  });

  type InitialValue = Yup.InferType<typeof ValidationScheme>;

  const initialValues: InitialValue = {
    email: "",
  };

  return (
    <>
      <Styled.SubTitle>{t("RECOVERY_PASS_SCREEN.INPUT_EMAIL")}</Styled.SubTitle>

      <Formik
        initialValues={initialValues}
        validationSchema={ValidationScheme}
        onSubmit={(values) => handleSubmit(values.email)}
      >
        {(props) => (
          <Styled.Form>
            <Styled.Field
              label={t("RECOVERY_PASS_SCREEN.EMAIL")}
              ariaLabel={t("RECOVERY_PASS_SCREEN.ARIA_INPUT_EMAIL")}
              name="email"
              type="email"
            />

            <Styled.Submit
              isLoading={isLoading}
              isDisabled={!props.isValid}
              text={t("RECOVERY_PASS_SCREEN.SUBMIT")}
              type="submit"
              rounded
            />

            <Styled.BackToLogin
              onClick={() => history.push("/auth")}
              outline
              text={t("RECOVERY_PASS_SCREEN.BACK")}
              rounded
            />
          </Styled.Form>
        )}
      </Formik>
      <Dialog
        isVisible={successDialogVisible}
        confirmText={t("RECOVERY_PASS_SCREEN.CONFIRM")}
        message={t("RECOVERY_PASS_SCREEN.SUCCESS")}
        onConfirm={() => history.push("/auth")}
      />
    </>
  );
}

export default SendEmailScreen;
