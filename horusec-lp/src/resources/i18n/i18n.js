import i18n from 'i18next';
import Backend from 'i18next-xhr-backend';
import LanguageDetector from 'i18next-browser-languagedetector';
import { initReactI18next } from 'react-i18next';

import ptBr from './locale/pt-br.json';
import enUs from './locale/en-us.json';

i18n
  .use(Backend)
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    fallbackLng: ['en', 'pt'],
    interpolation: {
      escapeValue: false, // not needed for react!!
    },
    keySeparator: false,
    resources: {
      'en-US': enUs,
      'pt-BR': ptBr,
      en: enUs,
      pt: ptBr,
    },
    // debug: true, // remove this after tests
  });

export default i18n;
