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

import React, { useState, FormEvent, useContext } from 'react';
import Styled from './styled';
import { useTranslation } from 'react-i18next';
import { Input } from 'components';
import { Field } from 'helpers/interfaces/Field';
import { isEmptyString } from 'helpers/validators';
import { useHistory } from 'react-router-dom';
import { CompanyContext } from 'contexts/Company';

function AddCompany() {
  const { t } = useTranslation();
  const history = useHistory();
  const [companyName, setCompanyName] = useState<Field>({
    isValid: false,
    value: '',
  });

  const { isLoading, createCompany } = useContext(CompanyContext);

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    if (companyName.isValid) {
      createCompany(companyName.value);
    }
  };

  return (
    <>
      <Styled.Title>{t('ADD_ORGANIZATION')}</Styled.Title>

      <Styled.SubTitle>{t('TYPE_ORGANIZATION_NAME')}</Styled.SubTitle>

      <Styled.Form onSubmit={handleSubmit}>
        <Input
          name="companyName"
          label={t('ORGANIZATION_NAME')}
          width="100%"
          onChangeValue={(field: Field) => setCompanyName(field)}
          validation={isEmptyString}
          invalidMessage={t('INVALID_ORGANIZATION_NAME')}
        />

        <Styled.OptionsWrapper>
          <Styled.Btn
            outline
            text={t('CANCEL')}
            width={100}
            height={40}
            onClick={() => history.push('/organization')}
          />

          <Styled.Btn
            isDisabled={!companyName.isValid}
            isLoading={isLoading}
            type="submit"
            text={t('SAVE')}
            width={100}
            height={40}
          />
        </Styled.OptionsWrapper>
      </Styled.Form>
    </>
  );
}

export default AddCompany;
