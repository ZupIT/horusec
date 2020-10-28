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
import companyService from 'services/company';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { Company } from 'helpers/interfaces/Company';
import { useHistory } from 'react-router-dom';
import { setCurrentCompany } from 'helpers/localStorage/currentCompany';
import useFlashMessage from 'helpers/hooks/useFlashMessage';
import { useTranslation } from 'react-i18next';

interface CompanyProviderPops {
  children: JSX.Element;
}

interface CompanyCtx {
  allCompanies: Company[];
  filteredCompanies: Company[];
  isLoading: boolean;
  fetchAll(): void;
  filterAllCompanies(search: string): void;
  createCompany(name: string, adminEmail?: string): void;
  updateCompany(companyId: string, name: string): void;
  removeCompany(companyId: string): void;
  handleCurrentCompany(companyId: string): void;
}

const CompanyContext = React.createContext<CompanyCtx>({
  allCompanies: [],
  filteredCompanies: [],
  fetchAll: null,
  isLoading: false,
  filterAllCompanies: null,
  createCompany: null,
  updateCompany: null,
  removeCompany: null,
  handleCurrentCompany: null,
});

const CompanyProvider = ({ children }: CompanyProviderPops) => {
  const [allCompanies, setAllCompanies] = useState<Company[]>([]);
  const [filteredCompanies, setFilteredCompanies] = useState<Company[]>([]);
  const [isLoading, setLoading] = useState(false);
  const { t } = useTranslation();

  const history = useHistory();
  const { dispatchMessage } = useResponseMessage();
  const { showSuccessFlash } = useFlashMessage();

  const filterAllCompanies = (search: string) => {
    if (search) {
      const filtered = allCompanies.filter((company) =>
        company.name.toLocaleLowerCase().includes(search.toLocaleLowerCase())
      );

      setFilteredCompanies(filtered);
    } else {
      setFilteredCompanies(allCompanies);
    }
  };

  const fetchAll = () => {
    setLoading(true);
    companyService
      .getAll()
      .then((result) => {
        const companies = result.data.content as Company[];
        setAllCompanies(companies);
        setFilteredCompanies(companies);
        setLoading(false);
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
        setLoading(false);
      });
  };

  const createCompany = (name: string, adminEmail?: string) => {
    setLoading(true);
    companyService
      .create(name, adminEmail)
      .then(() => {
        showSuccessFlash(t('COMPANY_SCREEN.CREATE_SUCCESS'));
        setLoading(false);
        history.push('/organization');
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
        setLoading(false);
      });
  };

  const updateCompany = (companyId: string, name: string) => {
    setLoading(true);
    companyService
      .update(companyId, name)
      .then(() => {
        showSuccessFlash(t('COMPANY_SCREEN.UPDATE_SUCCESS'));
        setLoading(false);
        history.push('/organization');
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
        setLoading(false);
      });
  };

  const removeCompany = (companyId: string) => {
    setLoading(true);
    companyService
      .remove(companyId)
      .then(() => {
        showSuccessFlash(t('COMPANY_SCREEN.REMOVE_SUCCESS'));
        fetchAll();
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
        setLoading(false);
      });
  };

  const handleCurrentCompany = (companyId: string) => {
    setLoading(true);
    companyService
      .getOne(companyId)
      .then((res) => {
        setCurrentCompany(res?.data?.content);
        history.push('/home');
      })
      .catch((err) => {
        dispatchMessage(err?.response?.data);
        setLoading(false);
      });
  };

  return (
    <CompanyContext.Provider
      value={{
        allCompanies,
        filteredCompanies,
        fetchAll,
        filterAllCompanies,
        createCompany,
        updateCompany,
        removeCompany,
        handleCurrentCompany,
        isLoading,
      }}
    >
      {children}
    </CompanyContext.Provider>
  );
};

export { CompanyContext, CompanyProvider };
