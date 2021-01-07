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

import http from 'config/axios/default';
import { SERVICE_ANALYTIC } from '../config/endpoints';
import { FilterValues } from 'helpers/interfaces/FilterValues';
import { formatInitialAndFinalDate } from 'helpers/formatters/date';

const getTotalDevelopers = (filters: FilterValues) => {
  let path;
  let ID;

  if (filters.type === 'workspace') {
    path = 'companies';
    ID = filters.companyID;
  } else {
    path = `companies/${filters.companyID}/repositories`;
    ID = filters.repositoryID;
  }

  return http.get(
    `${SERVICE_ANALYTIC}/api/dashboard/${path}/${ID}/total-developers`,
    {
      params: formatInitialAndFinalDate(filters.initialDate, filters.finalDate),
    }
  );
};

const getTotalRepositories = (filters: FilterValues) => {
  let path;
  let ID;

  if (filters.type === 'workspace') {
    path = 'companies';
    ID = filters.companyID;
  } else {
    path = `companies/${filters.companyID}/repositories`;
    ID = filters.repositoryID;
  }

  return http.get(
    `${SERVICE_ANALYTIC}/api/dashboard/${path}/${ID}/total-repositories`,
    {
      params: formatInitialAndFinalDate(filters.initialDate, filters.finalDate),
    }
  );
};

const getAllVulnerabilities = (filters: FilterValues) => {
  let path;
  let ID;

  if (filters.type === 'workspace') {
    path = 'companies';
    ID = filters.companyID;
  } else {
    path = `companies/${filters.companyID}/repositories`;
    ID = filters.repositoryID;
  }

  return http.get(
    `${SERVICE_ANALYTIC}/api/dashboard/${path}/${ID}/all-vulnerabilities`,
    {
      params: formatInitialAndFinalDate(filters.initialDate, filters.finalDate),
    }
  );
};

const getVulnerabilitiesByLanguage = (filters: FilterValues) => {
  let path;
  let ID;

  if (filters.type === 'workspace') {
    path = 'companies';
    ID = filters.companyID;
  } else {
    path = `companies/${filters.companyID}/repositories`;
    ID = filters.repositoryID;
  }

  return http.get(
    `${SERVICE_ANALYTIC}/api/dashboard/${path}/${ID}/vulnerabilities-by-language`,
    {
      params: formatInitialAndFinalDate(filters.initialDate, filters.finalDate),
    }
  );
};

const getVulnerabilitiesByDeveloper = (filters: FilterValues) => {
  let path;
  let ID;

  if (filters.type === 'workspace') {
    path = 'companies';
    ID = filters.companyID;
  } else {
    path = `companies/${filters.companyID}/repositories`;
    ID = filters.repositoryID;
  }

  return http.get(
    `${SERVICE_ANALYTIC}/api/dashboard/${path}/${ID}/vulnerabilities-by-author`,
    {
      params: formatInitialAndFinalDate(filters.initialDate, filters.finalDate),
    }
  );
};

const getVulnerabilitiesByRepository = (filters: FilterValues) => {
  let path;
  let ID;

  if (filters.type === 'workspace') {
    path = 'companies';
    ID = filters.companyID;
  } else {
    path = `companies/${filters.companyID}/repositories`;
    ID = filters.repositoryID;
  }

  return http.get(
    `${SERVICE_ANALYTIC}/api/dashboard/${path}/${ID}/vulnerabilities-by-repository`,
    {
      params: formatInitialAndFinalDate(filters.initialDate, filters.finalDate),
    }
  );
};

const getVulnerabilitiesTimeLine = (filters: FilterValues) => {
  let path;
  let ID;

  if (filters.type === 'workspace') {
    path = 'companies';
    ID = filters.companyID;
  } else {
    path = `companies/${filters.companyID}/repositories`;
    ID = filters.repositoryID;
  }

  return http.get(
    `${SERVICE_ANALYTIC}/api/dashboard/${path}/${ID}/vulnerabilities-by-time`,
    {
      params: formatInitialAndFinalDate(filters.initialDate, filters.finalDate),
    }
  );
};

const getVulnerabilitiesDetails = (
  filters: FilterValues,
  page: number,
  size: number
) => {
  let filter;
  let path;
  let ID;

  if (filters.type === 'workspace') {
    filter = `companyID: "${filters.companyID}"`;
    path = 'companies';
    ID = filters.companyID;
  } else {
    filter = `repositoryID: "${filters.repositoryID}"`;
    path = `companies/${filters.companyID}/repositories`;
    ID = filters.repositoryID;
  }

  const { initialDate, finalDate } = formatInitialAndFinalDate(
    filters.initialDate,
    filters.finalDate
  );

  const query = `{
    totalItems(${filter}, initialDate: "${initialDate}", finalDate: "${finalDate}")
    analysis (${filter}, initialDate: "${initialDate}", finalDate: "${finalDate}"){
      repositoryName
      companyName
      vulnerability {
        line
        column
        confidence
        file
        code
        details
        securityTool
        language
        severity
        commitAuthor
        commitEmail
        commitHash
        commitMessage
        commitDate
      }
    }
  }`;

  return http.get(`${SERVICE_ANALYTIC}/api/dashboard/${path}/${ID}/details`, {
    params: { query, page, size },
  });
};

export default {
  getTotalDevelopers,
  getTotalRepositories,
  getAllVulnerabilities,
  getVulnerabilitiesByDeveloper,
  getVulnerabilitiesByLanguage,
  getVulnerabilitiesByRepository,
  getVulnerabilitiesTimeLine,
  getVulnerabilitiesDetails,
};
