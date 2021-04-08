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
declare global {
  interface Window {
    REACT_APP_HORUSEC_ENDPOINT_ACCOUNT: string;
    REACT_APP_HORUSEC_ENDPOINT_API: string;
    REACT_APP_HORUSEC_ENDPOINT_ANALYTIC: string;
    REACT_APP_HORUSEC_ENDPOINT_AUTH: string;
  }
}

const SERVICE_ACCOUNT =
  window.REACT_APP_HORUSEC_ENDPOINT_ACCOUNT || 'http://127.0.0.1:8003';

const SERVICE_API =
  window.REACT_APP_HORUSEC_ENDPOINT_API || 'http://127.0.0.1:8000';

const SERVICE_ANALYTIC =
  window.REACT_APP_HORUSEC_ENDPOINT_ANALYTIC || 'http://127.0.0.1:8005';

const SERVICE_AUTH =
  window.REACT_APP_HORUSEC_ENDPOINT_AUTH || 'http://127.0.0.1:8006';

const isLocalHost = (endpoint: string) =>
  endpoint.includes('localhost') || endpoint.includes('127.0.0.1');

if (
  isLocalHost(SERVICE_AUTH) ||
  isLocalHost(SERVICE_ACCOUNT) ||
  isLocalHost(SERVICE_API) ||
  isLocalHost(SERVICE_ANALYTIC)
) {
  console.warn(`📡 One or more addresses of Horusec services have not been defined
or have been defined as localhost.
If this is not the scenario for your application, visit the guide:
How to run the web application in other host?
https://horusec.io/docs/tutorials/how-to-run-the-web-application-on-other-host`);
}

export { SERVICE_ACCOUNT, SERVICE_API, SERVICE_ANALYTIC, SERVICE_AUTH };
