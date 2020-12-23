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

const isLocalHost =
  window.location.origin.includes('localhost') ||
  window.location.origin.includes('127.0.0.1');

function API_HOST(ENV_ENDPOINT: any) {
  if (!ENV_ENDPOINT) {
    return window.location.origin;
  }

  return ENV_ENDPOINT;
}

const SERVICE_ACCOUNT = isLocalHost
  ? 'http://127.0.0.1:8003'
  : API_HOST((window as any).REACT_APP_HORUSEC_ENDPOINT_ACCOUNT);

const SERVICE_API = isLocalHost
  ? 'http://127.0.0.1:8000'
  : API_HOST((window as any).REACT_APP_HORUSEC_ENDPOINT_API);

const SERVICE_ANALYTIC = isLocalHost
  ? 'http://127.0.0.1:8005'
  : API_HOST((window as any).REACT_APP_HORUSEC_ENDPOINT_ANALYTIC);

const SERVICE_AUTH = isLocalHost
  ? 'http://127.0.0.1:8006'
  : API_HOST((window as any).REACT_APP_HORUSEC_ENDPOINT_AUTH);

export { SERVICE_ACCOUNT, SERVICE_API, SERVICE_ANALYTIC, SERVICE_AUTH };
