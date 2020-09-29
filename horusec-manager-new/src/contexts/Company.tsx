import React, { useState } from 'react';
import companyService from 'services/company';
import useResponseMessage from 'helpers/hooks/useResponseMessage';
import { Company } from 'helpers/interfaces/Company';
import { useHistory } from 'react-router-dom';
import { setCurrentCompany } from 'helpers/localStorage/currentCompany';

interface CompanyProviderPops {
  children: JSX.Element;
}

interface CompanyCtx {
  allCompanies: Company[];
  filteredCompanies: Company[];
  fetchAll: Function;
  isLoading: boolean;
  filterAllCompanies: Function;
  createCompany: Function;
  updateCompany: Function;
  removeCompany: Function;
  handleCurrentCompany: Function;
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

  const history = useHistory();
  const { dispatchMessage } = useResponseMessage();

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

  const createCompany = (name: string) => {
    setLoading(true);
    companyService
      .create(name)
      .then(() => {
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
