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

const isLocalHost = window.location.origin.includes('localhost');

function API_HOST() {
  const ENV_ENDPOINT = (window as any).REACT_APP_HORUSEC_ENDPOINT;

  if (!ENV_ENDPOINT) {
    return isLocalHost ? 'http://localhost' : window.location.host;
  } else {
    return ENV_ENDPOINT;
  }
}

const SERVICE_ACCOUNT = isLocalHost
  ? `${API_HOST()}:8003`
  : `://account-horusec.${API_HOST()}`;

const SERVICE_API = isLocalHost
  ? `${API_HOST()}:8000`
  : `://api-horusec.${API_HOST()}`;

const SERVICE_ANALYTIC = isLocalHost
  ? `${API_HOST()}:8005`
  : `://analytic-horusec.${API_HOST()}`;

export { SERVICE_ACCOUNT, SERVICE_API, SERVICE_ANALYTIC };
