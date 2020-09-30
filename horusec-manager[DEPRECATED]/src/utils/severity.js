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

export const ColorsBySeverity = {
  HIGH: '#FF0000',
  MEDIUM: '#FF6600',
  LOW: '#FFEE00',
  NOSEC: '#0D47A1',
  AUDIT: '#A200FF',
  INFO: '#00ffcc'
}

export const ColorsByLanguage = {
  LEAKS: '#6e2971',
  GO: '#56DBE5',
  PYTHON: '#3b77a8',
  JAVASCRIPT: '#26C439',
  JAVA: '#D6BA32',
  KOTLIN: '#ED7D31',
  RUBY: '#AA1401',
  'C#': '#2A0072'
}

export function GetSeverityList () {
  return [
    'HIGH',
    'MEDIUM',
    'LOW',
    'NOSEC',
    'AUDIT',
    'INFO'
  ]
}


export function GetPositionByLabel (label) {
  if (label === 'HIGH') {
    return 0
  }
  if (label === 'MEDIUM') {
    return 1
  }
  if (label === 'LOW') {
    return 2
  }
  if (label === 'NOSEC') {
    return 3
  }
  if (label === 'AUDIT') {
    return 4
  }
  if (label === 'INFO') {
    return 5
  }
}
