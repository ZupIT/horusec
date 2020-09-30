import React, { useState, FormEvent, useContext, useEffect } from 'react';
import Styled from './styled';
import { useTranslation } from 'react-i18next';
import { Input } from 'components';
import { Field } from 'helpers/interfaces/Field';
import { isEmptyString } from 'helpers/validators';
import { useHistory, useParams } from 'react-router-dom';
import { CompanyContext } from 'contexts/Company';

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

  const { isLoading, updateCompany } = useContext(CompanyContext);

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    if (companyName.isValid) {
      updateCompany(companyId, companyName.value);
    }
  };

  useEffect(() => {
    setCompanyName({ isValid: false, value: state.companyName });
  }, [state]);

  return (
    <>
      <Styled.Title>{t('EDIT_ORGANIZATION_NAME')}</Styled.Title>

      <Styled.SubTitle>{t('TYPE_ORGANIZATION_NAME')}</Styled.SubTitle>

      <Styled.Form onSubmit={handleSubmit}>
        <Input
          name="companyName"
          label={t('ORGANIZATION_NAME')}
          width="100%"
          onChangeValue={(field: Field) => setCompanyName(field)}
          validation={isEmptyString}
          invalidMessage={t('INVALID_ORGANIZATION_NAME')}
          initialValue={companyName.value}
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

export default EditCompany;
