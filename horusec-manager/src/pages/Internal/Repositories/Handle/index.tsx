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
import repositoryService from 'services/repository';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import { getCurrentConfig } from 'helpers/localStorage/horusecConfig';
import { authTypes } from 'helpers/enums/authTypes';
import { getCurrentUser } from 'helpers/localStorage/currentUser';
import { Repository } from 'helpers/interfaces/Repository';
import useWorkspace from 'helpers/hooks/useWorkspace';
import { FieldArray, Formik, FormikHelpers } from 'formik';
import * as Yup from 'yup';

interface Props {
  isVisible: boolean;
  repositoryToEdit?: Repository;
  onCancel: () => void;
  onConfirm: () => void;
}

const HandleRepository: React.FC<Props> = ({
  isVisible,
  onCancel,
  onConfirm,
  repositoryToEdit,
}) => {
  const { t } = useTranslation();
  const { colors } = useTheme();
  const currentUser = getCurrentUser();
  const { dispatchMessage } = useResponseMessage();
  const { showSuccessFlash } = useFlashMessage();
  const { applicationAdminEnable } = getCurrentConfig();
  const { currentWorkspace } = useWorkspace();

  const [isLoading, setLoading] = useState(false);

  const handleCreate = (
    values: InitialValue,
    actions: FormikHelpers<InitialValue>
  ) => {
    repositoryService
      .create(currentWorkspace.companyID, values.name, values.description, {
        authzAdmin: values.authzAdmin,
        authzMember: values.authzMember,
        authzSupervisor: values.authzSupervisor,
      })
      .then(() => {
        onConfirm();
        showSuccessFlash(t('REPOSITORIES_SCREEN.SUCCESS_CREATE_REPO'));
        actions.resetForm();
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
      })
      .finally(() => {
        setLoading(false);
      });
  };

  const handleEdit = (
    values: InitialValue,
    actions: FormikHelpers<InitialValue>
  ) => {
    repositoryService
      .update(
        repositoryToEdit.companyID,
        repositoryToEdit.repositoryID,
        values.name,
        values.description,
        {
          authzAdmin: values.authzAdmin,
          authzMember: values.authzMember,
          authzSupervisor: values.authzSupervisor,
        }
      )
      .then(() => {
        onConfirm();
        showSuccessFlash(t('REPOSITORIES_SCREEN.SUCCESS_EDIT_REPO'));
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
    authzSupervisor: Yup.array<string[]>().notRequired(),
  });

  type InitialValue = Yup.InferType<typeof ValidationScheme>;

  const initialValues: InitialValue = {
    name: repositoryToEdit?.name || '',
    description: repositoryToEdit?.description || '',
    emailAdmin: currentUser?.email || '',
    authzAdmin: repositoryToEdit?.authzAdmin || [''],
    authzMember: repositoryToEdit?.authzMember || [''],
    authzSupervisor: repositoryToEdit?.authzSupervisor || [''],
  };

  return (
    <Formik
      initialValues={initialValues}
      enableReinitialize={true}
      validationSchema={ValidationScheme}
      onSubmit={(values, actions) => {
        setLoading(true);
        repositoryToEdit
          ? handleEdit(values, actions)
          : handleCreate(values, actions);
      }}
    >
      {(props) => (
        <Dialog
          isVisible={isVisible}
          message={
            repositoryToEdit
              ? t('REPOSITORIES_SCREEN.EDIT_REPO')
              : t('REPOSITORIES_SCREEN.CREATE_REPO')
          }
          onCancel={() => {
            props.resetForm();
            onCancel();
          }}
          onConfirm={props.submitForm}
          confirmText={t('REPOSITORIES_SCREEN.SAVE')}
          disableConfirm={!props.isValid}
          disabledColor={colors.button.disableInDark}
          loadingConfirm={isLoading}
          width={600}
          hasCancel
        >
          <Styled.Form>
            <Styled.Field
              name="name"
              label={t('REPOSITORIES_SCREEN.NAME')}
              width="100%"
            />

            <Styled.Field
              name="description"
              label={t('REPOSITORIES_SCREEN.DESCRIPTION')}
              width="100%"
            />

            {applicationAdminEnable && (
              <Styled.Wrapper>
                <Styled.Label>
                  {t('REPOSITORIES_SCREEN.ADMIN_EMAIL')}
                </Styled.Label>

                <Input
                  name="emailAdmin"
                  label={t('REPOSITORIES_SCREEN.EMAIL')}
                />
              </Styled.Wrapper>
            )}

            {getCurrentConfig().authType === authTypes.LDAP && (
              <>
                <Styled.SubTitle>
                  {t('REPOSITORIES_SCREEN.REFERENCE_GROUP')}
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

                <Styled.WrapperColumn>
                  <Styled.Label>
                    {t('REPOSITORIES_SCREEN.SUPERVISOR')}
                  </Styled.Label>
                  <FieldArray name="authzSupervisor">
                    {({ push, remove }) => {
                      const { authzSupervisor } = props.values;
                      return authzSupervisor.map((_, index) => (
                        <Styled.Wrapper key={index}>
                          <Input
                            name={`authzSupervisor.${index}`}
                            label={t('REPOSITORIES_SCREEN.GROUP_NAME')}
                          />

                          {index + 1 === authzSupervisor.length &&
                          authzSupervisor.length !== 1 ? (
                            <Styled.OptionIcon
                              name="delete"
                              size="20px"
                              onClick={() => remove(index)}
                            />
                          ) : null}

                          {index + 1 === authzSupervisor.length &&
                          authzSupervisor.length !== 5 ? (
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

export default HandleRepository;
