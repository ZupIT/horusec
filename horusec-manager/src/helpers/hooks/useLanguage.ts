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

import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Language as LanguageItem } from 'helpers/interfaces/Language';
import {
  getCurrentLanguage,
  setCurrentLanguage,
} from 'helpers/localStorage/currentLanguage';

const allLanguages: LanguageItem[] = [
  {
    name: 'en - US',
    i18nValue: 'enUS',
    htmlValue: 'en',
    icon: 'united-states',
    dateFormat: 'MM/dd/yyyy',
  },
  {
    name: 'pt - BR',
    i18nValue: 'ptBR',
    htmlValue: 'pt-br',
    icon: 'brazil',
    dateFormat: 'dd/MM/yyyy',
  },
];

const useLanguage = () => {
  const [currentLanguage, setLanguage] = useState(allLanguages[0]);
  const { i18n } = useTranslation();

  const setUserLanguage = (lang: LanguageItem) => {
    setLanguage(lang);
    setCurrentLanguage(lang);

    i18n.changeLanguage(lang.i18nValue);
    window.document.documentElement.lang = lang.htmlValue;
  };

  useEffect(() => {
    const defaultLanguage = getCurrentLanguage();

    setUserLanguage(defaultLanguage || allLanguages[0]);

    // eslint-disable-next-line
  }, []);

  return {
    allLanguages,
    currentLanguage,
    setUserLanguage,
  };
};

export default useLanguage;
