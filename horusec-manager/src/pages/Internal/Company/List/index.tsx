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

import { Icon, Dialog } from 'components';
import { CompanyContext } from 'contexts/Company';
import useOutsideClick from 'helpers/hooks/useClickOutside';
import React, { useContext, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useHistory } from 'react-router-dom';
import Styled from './styled';
import { Company } from 'helpers/interfaces/Company';
import { isApplicationAdmin } from 'helpers/localStorage/currentUser';

import Tokens from './Tokens';

function ListCompanies() {
  const { t } = useTranslation();
  const history = useHistory();

  const [selectedCompany, setSelectedCompany] = useState<Company>(null);
  const [companyToDelete, setCompanyToDelete] = useState<Company>(null);
  const [companyToManagerTokens, setCompanyToManagerTokens] = useState<Company>(
    null
  );

  const {
    isLoading,
    fetchAll,
    removeCompany,
    filterAllCompanies,
    filteredCompanies,
    handleCurrentCompany,
  } = useContext(CompanyContext);

  const ref = useRef<HTMLUListElement>();

  useOutsideClick(ref, () => {
    if (selectedCompany) setSelectedCompany(null);
  });

  // eslint-disable-next-line
  useEffect(() => fetchAll(), []);

  return (
    <>
      <Styled.Title>{t('COMPANY_SCREEN.SELECT_ORGANIZATION')}</Styled.Title>

      <Styled.OptionsWrapper>
        {isApplicationAdmin() ? (
          <Styled.AddCompanyBtn
            onClick={() => history.push('/organization/add')}
          >
            <Icon name="add" size="16px" />

            <Styled.TextBtn>
              {t('COMPANY_SCREEN.ADD_ORGANIZATION')}
            </Styled.TextBtn>
          </Styled.AddCompanyBtn>
        ) : null}

        <Styled.SearchWrapper>
          <Styled.SearchInput
            onChange={(e) => filterAllCompanies(e.target.value)}
          />

          <Icon name="search" size="16px" />
        </Styled.SearchWrapper>
      </Styled.OptionsWrapper>

      <Styled.ListWrapper>
        <Styled.List>
          {isLoading ? (
            <>
              <Styled.Shimmer />
              <Styled.Shimmer />
              <Styled.Shimmer />
            </>
          ) : null}

          {filteredCompanies.length <= 0 && !isLoading ? (
            <Styled.NoItem>
              <Styled.ItemText>
                {t('COMPANY_SCREEN.NO_ORGANIZATIONS')}
              </Styled.ItemText>
            </Styled.NoItem>
          ) : null}

          {filteredCompanies.map((company) => (
            <Styled.Item
              key={company.companyID}
              selected={selectedCompany?.companyID === company.companyID}
            >
              <Styled.ItemText
                onClick={() => handleCurrentCompany(company.companyID)}
              >
                {company.name}
              </Styled.ItemText>

              {company?.role === 'admin' ? (
                <Styled.SettingsIcon
                  onClick={() => setSelectedCompany(company)}
                  name="settings"
                />
              ) : null}

              <Styled.Settings
                ref={ref}
                isVisible={selectedCompany?.companyID === company.companyID}
              >
                <Styled.SettingsItem
                  onClick={() =>
                    history.push(`/organization/edit/${company.companyID}`, {
                      companyName: company.name,
                    })
                  }
                >
                  {t('COMPANY_SCREEN.EDIT')}
                </Styled.SettingsItem>

                <Styled.SettingsItem
                  onClick={() => setCompanyToDelete(company)}
                >
                  {t('COMPANY_SCREEN.REMOVE')}
                </Styled.SettingsItem>

                <Styled.SettingsItem
                  onClick={() => setCompanyToManagerTokens(company)}
                >
                  {t('COMPANY_SCREEN.TOKENS')}
                </Styled.SettingsItem>
              </Styled.Settings>
            </Styled.Item>
          ))}
        </Styled.List>
      </Styled.ListWrapper>

      <Dialog
        hasCancel
        defaultButton
        isVisible={!!companyToDelete}
        confirmText={t('COMPANY_SCREEN.YES')}
        message={`${t('COMPANY_SCREEN.CONFIRM_DELETE_ORGANIZATION')} ${
          companyToDelete?.name
        } ?`}
        onConfirm={() => {
          removeCompany(companyToDelete?.companyID);
          setCompanyToDelete(null);
        }}
        onCancel={() => setCompanyToDelete(null)}
      />

      <Tokens
        isVisible={!!companyToManagerTokens}
        selectedCompany={companyToManagerTokens}
        onClose={() => setCompanyToManagerTokens(null)}
      />
    </>
  );
}

export default ListCompanies;
