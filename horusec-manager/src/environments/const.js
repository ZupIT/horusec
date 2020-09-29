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

const isLocalHost = window.location.origin.includes('localhost')

export function API_HOST () {
  if (!isLocalHost) {
    return window.location.origin
  }

  return 'http://localhost'
}

export const END_POINTS = {
  SERVICE_ACCOUNT: isLocalHost ? ':8003' : '/service_account',
  SERVICE_API: isLocalHost ? ':8000' : '/service_api',
  SERVICE_ANALYTIC: isLocalHost ? ':8005' : '/service_analytic'
}
