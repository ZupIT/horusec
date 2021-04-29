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

import React, { useState } from 'react';
import { Dialog, Input } from 'components';
import { useTranslation } from 'react-i18next';
import Styled from './styled';
import { useTheme } from 'styled-components';
import companyService from 'services/company';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import { getCurrentConfig } from 'helpers/localStorage/horusecConfig';
import { authTypes } from 'helpers/enums/authTypes';
import { getCurrentUser } from 'helpers/localStorage/currentUser';
import { Workspace } from 'helpers/interfaces/Workspace';
import { FieldArray, Formik, FormikHelpers } from 'formik';
import * as Yup from 'yup';

interface Props {
  isVisible: boolean;
  workspaceToEdit?: Workspace;
  onCancel: () => void;
  onConfirm: () => void;
}

const HandleWorkspace: React.FC<Props> = ({
  isVisible,
  onCancel,
  onConfirm,
  workspaceToEdit,
}) => {
  const { t } = useTranslation();
  const { colors } = useTheme();
  const currentUser = getCurrentUser();
  const { dispatchMessage } = useResponseMessage();
  const { showSuccessFlash } = useFlashMessage();
  const { applicationAdminEnable } = getCurrentConfig();

  const [isLoading, setLoading] = useState(false);

  const handleCreate = (
    values: InitialValue,
    actions: FormikHelpers<InitialValue>
  ) => {
    companyService
      .create(values.name, values.description, values.emailAdmin, {
        authzAdmin: values.authzAdmin,
        authzMember: values.authzMember,
      })
      .then(() => {
        onConfirm();
        showSuccessFlash(t('WORKSPACES_SCREEN.CREATE_SUCCESS'));
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      })
      .finally(() => {
        setLoading(false);
        actions.resetForm();
      });
  };

  const handleEdit = (
    values: InitialValue,
    actions: FormikHelpers<InitialValue>
  ) => {
    companyService
      .update(
        workspaceToEdit.companyID,
        values.name,
        values.description,
        values.emailAdmin,
        {
          authzAdmin: values.authzAdmin,
          authzMember: values.authzMember,
        }
      )
      .then(() => {
        onConfirm();
        showSuccessFlash(t('WORKSPACES_SCREEN.UPDATE_SUCCESS'));
        actions.resetForm();
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      })
      .finally(() => {
        setLoading(false);
      });
  };

  const ValidationScheme = Yup.object({
    name: Yup.string().required(),
    description: Yup.string().optional(),
    emailAdmin: Yup.string().required(),
    authzAdmin: Yup.array<string[]>().notRequired(),
    authzMember: Yup.array<string[]>().notRequired(),
  });

  type InitialValue = Yup.InferType<typeof ValidationScheme>;

  const initialValues: InitialValue = {
    name: workspaceToEdit?.name || '',
    description: workspaceToEdit?.description || '',
    emailAdmin: currentUser?.email || '',
    authzAdmin: workspaceToEdit?.authzAdmin || [''],
    authzMember: workspaceToEdit?.authzMember || [''],
  };

  return (
    <Formik
      initialValues={initialValues}
      enableReinitialize={true}
      validationSchema={ValidationScheme}
      onSubmit={(values, actions) => {
        setLoading(true);
        workspaceToEdit
          ? handleEdit(values, actions)
          : handleCreate(values, actions);
      }}
    >
      {(props) => (
        <Dialog
          isVisible={isVisible}
          message={
            workspaceToEdit
              ? t('WORKSPACES_SCREEN.EDIT_WORKSPACE')
              : t('WORKSPACES_SCREEN.ADD')
          }
          onCancel={() => {
            props.resetForm();
            onCancel();
          }}
          onConfirm={props.submitForm}
          confirmText={t('WORKSPACES_SCREEN.SAVE')}
          disableConfirm={!props.isValid}
          disabledColor={colors.button.disableInDark}
          loadingConfirm={isLoading}
          width={600}
          hasCancel
        >
          <Styled.Form>
            <Styled.Field
              name="name"
              label={t('WORKSPACES_SCREEN.TABLE.NAME')}
              width="100%"
            />

            <Styled.Field
              name="description"
              label={t('WORKSPACES_SCREEN.TABLE.DESCRIPTION')}
              width="100%"
            />

            {applicationAdminEnable && (
              <Styled.Wrapper>
                <Styled.Label>
                  {t('WORKSPACES_SCREEN.ADMIN_EMAIL')}
                </Styled.Label>

                <Input name="emailAdmin" label={t('WORKSPACES_SCREEN.EMAIL')} />
              </Styled.Wrapper>
            )}

            {getCurrentConfig().authType === authTypes.LDAP && (
              <>
                <Styled.SubTitle>
                  {t('WORKSPACES_SCREEN.REFERENCE_GROUP')}
                </Styled.SubTitle>

                <Styled.WrapperColumn>
                  <Styled.Label>{t('WORKSPACES_SCREEN.ADMIN')}</Styled.Label>
                  <FieldArray name="authzAdmin">
                    {({ push, remove }) => {
                      const { authzAdmin } = props.values;
                      return authzAdmin.map((_, index) => (
                        <Styled.Wrapper key={index}>
                          <Input
                            name={`authzAdmin.${index}`}
                            label={t('WORKSPACES_SCREEN.GROUP_NAME')}
                          />

                          {index + 1 === authzAdmin.length &&
                          authzAdmin.length !== 1 ? (
                            <Styled.OptionIcon
                              name="delete"
                              size="20px"
                              onClick={() => remove(index)}
                            />
                          ) : null}

                          {index + 1 === authzAdmin.length &&
                          authzAdmin.length !== 5 ? (
                            <Styled.OptionIcon
                              name="plus"
                              size="20px"
                              onClick={() => push('')}
                            />
                          ) : null}
                        </Styled.Wrapper>
                      ));
                    }}
                  </FieldArray>
                </Styled.WrapperColumn>

                <Styled.WrapperColumn>
                  <Styled.Label>{t('WORKSPACES_SCREEN.MEMBER')}</Styled.Label>
                  <FieldArray name="authzMember">
                    {({ push, remove }) => {
                      const { authzMember } = props.values;
                      return authzMember.map((_, index) => (
                        <Styled.Wrapper key={index}>
                          <Input
                            name={`authzMember.${index}`}
                            label={t('WORKSPACES_SCREEN.GROUP_NAME')}
                          />

                          {index + 1 === authzMember.length &&
                          authzMember.length !== 1 ? (
                            <Styled.OptionIcon
                              name="delete"
                              size="20px"
                              onClick={() => remove(index)}
                            />
                          ) : null}

                          {index + 1 === authzMember.length &&
                          authzMember.length !== 5 ? (
                            <Styled.OptionIcon
                              name="plus"
                              size="20px"
                              onClick={() => push('')}
                            />
                          ) : null}
                        </Styled.Wrapper>
                      ));
                    }}
                  </FieldArray>
                </Styled.WrapperColumn>
              </>
            )}
          </Styled.Form>
        </Dialog>
      )}
    </Formik>
  );
};

export default HandleWorkspace;
