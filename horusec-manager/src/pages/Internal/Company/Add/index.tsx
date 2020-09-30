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
      <Styled.Title>{t('COMPANY_SCREEN.ADD_ORGANIZATION')}</Styled.Title>

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
        />

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

export default AddCompany;
