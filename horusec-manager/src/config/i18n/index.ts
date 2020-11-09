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

import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import { getCurrentLanguage } from 'helpers/localStorage/currentLanguage';

import enUSTranslation from './enUS.json';
import ptBRTranslation from './ptBR.json';

const currentLanguage = getCurrentLanguage();

const resources = {
  ptBR: {
    translation: ptBRTranslation,
  },
  enUS: {
    translation: enUSTranslation,
  },
};

i18n.use(initReactI18next).init({
  resources,
  lng: currentLanguage?.i18nValue || 'enUS',

  keySeparator: '.',

  returnObjects: true,

  interpolation: {
    escapeValue: false,
  },
});

export default i18n;
