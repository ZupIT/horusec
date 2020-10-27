import React, {useState} from 'react';
import LanguageCodes from '../../resources/i18n/enum';
import { useTranslation } from 'react-i18next';
import View from './header-view';

export default () => {
  const { t, i18n } = useTranslation('LandingPage', { useSuspense: false });

  const [language, setLanguage] = useState(LanguageCodes[i18n.language] || 'English');
  const [isLanguageMenuOpen, setisLanguageMenuOpen] = useState(false);

  const handleLanguageChange = (value, label) => {
    setLanguage(label);
    setisLanguageMenuOpen(false);

    i18n.changeLanguage(value);
  };

  const languages = [
    {
      id: 1,
      label: 'Português',
      value: 'pt',
      action: (e) => {
        handleLanguageChange(e.target.dataset.value, e.target.dataset.label);
      },
    },
    {
      id: 2,
      label: 'English',
      value: 'en',
      action: (e) => {
        handleLanguageChange(e.target.dataset.value, e.target.dataset.label);
      },
    },
  ];

  const menu = [
    {
      id: 1,
      content: (
        <a href={t('Link Github')} target="_blank" rel="noreferrer">
          {t('Github')}
        </a>
      ),
    },
    {
      id: 2,
      content: (
        <a href={t('Link Docs')} target="_blank" rel="noreferrer">
          {t('Docs')}
        </a>
      ),
    }
  ];

  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

  const toggleMobileMenu = (e) => {
    e.preventDefault();

    setIsSidebarOpen(!isSidebarOpen);
  };

  return (
    <View menuItems={menu} languageItems={languages} languageValue={language} isLanguageDropdownOpen={isLanguageMenuOpen} isMobileMenuOpen={isSidebarOpen} toggleMobileMenu={toggleMobileMenu} />
  );
};
