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

import React, { useState, FormEvent, useContext, useEffect } from 'react';
import Styled from './styled';
import { useTranslation } from 'react-i18next';
import { Input } from 'components';
import { Field } from 'helpers/interfaces/Field';
import { isEmptyString } from 'helpers/validators';
import { useHistory, useParams } from 'react-router-dom';
import { CompanyContext } from 'contexts/Company';
import { authTypes } from 'helpers/enums/authTypes';
import { getCurrentAuthType } from 'helpers/localStorage/currentAuthType';

interface RouterStateProps {
  companyName: string;
}
interface RouterLocationProps {
  state: RouterStateProps;
}

function EditCompany({
  location: { state },
}: {
  location: RouterLocationProps;
}) {
  const { t } = useTranslation();
  const { companyId } = useParams();
  const history = useHistory();
  const [companyName, setCompanyName] = useState<Field>({
    isValid: false,
    value: '',
  });

  const [adminGroup, setAdminGroup] = useState<Field>({
    isValid: false,
    value: '',
  });

  const [userGroup, setUserGroup] = useState<Field>({
    isValid: false,
    value: '',
  });

  const { isLoading, updateCompany } = useContext(CompanyContext);

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    if (companyName.isValid) {
      updateCompany(companyId, companyName.value);

      // TODO: Remover este console.log
      console.log(adminGroup, userGroup);
    }
  };

  useEffect(() => {
    setCompanyName({ isValid: false, value: state.companyName });
  }, [state]);

  return (
    <>
      <Styled.Title>{t('COMPANY_SCREEN.EDIT_ORGANIZATION_NAME')}</Styled.Title>

      <Styled.SubTitle>
        {t('COMPANY_SCREEN.TYPE_ORGANIZATION_NAME')}
      </Styled.SubTitle>

      <Styled.Form onSubmit={handleSubmit}>
        <Input
          name="companyName"
          label={t('COMPANY_SCREEN.ORGANIZATION_NAME')}
          width="100%"
          onChangeValue={(field: Field) => setCompanyName(field)}
          validation={isEmptyString}
          invalidMessage={t('COMPANY_SCREEN.INVALID_ORGANIZATION_NAME')}
          initialValue={companyName.value}
        />

        {getCurrentAuthType() === authTypes.LDAP ? (
          <>
            <Styled.SubTitle>
              {t('COMPANY_SCREEN.REFERENCE_GROUP')}
            </Styled.SubTitle>

            <Styled.Wrapper>
              <Styled.Label>{t('COMPANY_SCREEN.ADMIN')}</Styled.Label>

              <Input
                name="adminGroup"
                label={t('COMPANY_SCREEN.GROUP_NAME')}
                onChangeValue={(field: Field) => setAdminGroup(field)}
              />
            </Styled.Wrapper>

            <Styled.Wrapper>
              <Styled.Label>{t('COMPANY_SCREEN.USER')}</Styled.Label>

              <Input
                name="userGroup"
                label={t('COMPANY_SCREEN.GROUP_NAME')}
                onChangeValue={(field: Field) => setUserGroup(field)}
              />
            </Styled.Wrapper>
          </>
        ) : null}

        <Styled.OptionsWrapper>
          <Styled.Btn
            outline
            text={t('COMPANY_SCREEN.CANCEL')}
            width={100}
            height={40}
            onClick={() => history.push('/organization')}
          />

          <Styled.Btn
            isDisabled={!companyName.isValid}
            isLoading={isLoading}
            type="submit"
            text={t('COMPANY_SCREEN.SAVE')}
            width={100}
            height={40}
          />
        </Styled.OptionsWrapper>
      </Styled.Form>
    </>
  );
}

export default EditCompany;
