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

let SERVICE_ACCOUNT = window.location.origin.replace(
  'manager-horusec',
  'account-horusec'
);
let SERVICE_API = window.location.origin.replace(
  'manager-horusec',
  'api-horusec'
);
let SERVICE_ANALYTIC = window.location.origin.replace(
  'manager-horusec',
  'analytics-horusec'
);

if (isLocalHost) {
  SERVICE_ACCOUNT = 'http://localhost:8003';
  SERVICE_API = 'http://localhost:8000';
  SERVICE_ANALYTIC = 'http://localhost:8005';
}

export { SERVICE_ACCOUNT, SERVICE_API, SERVICE_ANALYTIC };
