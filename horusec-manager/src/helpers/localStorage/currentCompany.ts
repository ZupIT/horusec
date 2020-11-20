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

import { localStorageKeys } from 'helpers/enums/localStorageKeys';
import { Company } from 'helpers/interfaces/Company';
import { setLocalStorage, getLocalStorage, removeLocalStorage } from 'helpers/localStorage/base';

const getCurrentCompany = (): Company | null => {
  const localData: Company = JSON.parse(
    getLocalStorage(localStorageKeys.COMPANY)
  );

  return localData;
};

const setCurrentCompany = (value: Company) => {
  const company = JSON.stringify(value);
  setLocalStorage(localStorageKeys.COMPANY, company);
};

const clearCurrentCompany = () => {
  removeLocalStorage(localStorageKeys.COMPANY);
};

const isAdminOfCompany = (): boolean => {
  const currentCompany = getCurrentCompany();

  if (currentCompany) {
    const { role } = currentCompany;
    return role === 'admin';
  } else {
    return false;
  }
};

const userRoleInCurrentCompany = (): string => {
  const currentCompany = getCurrentCompany();
  return currentCompany?.role;
};

export {
  getCurrentCompany,
  setCurrentCompany,
  clearCurrentCompany,
  isAdminOfCompany,
  userRoleInCurrentCompany,
};
