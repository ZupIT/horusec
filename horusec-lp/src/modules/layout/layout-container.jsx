import React, { useState } from 'react';
import { CookiesProvider, useCookies } from 'react-cookie';
import View from './layout-view';
import CookieComponent from '../../components/cookie';
import { useTranslation } from 'react-i18next';

export default ({ page, children }) => {
  const { i18n } = useTranslation('LandingPage', { useSuspense: false });

  const [cookies, setCookie] = useCookies(['zup-accepted-lgpd']);
  const [isCookieModalOpen, setIsCookieModalOpen] = useState(!Boolean(cookies['zup-accepted-lgpd']));

  const onAcceptCookie = () => {
    setIsCookieModalOpen(false);
    setCookie('zup-accepted-lgpd', true);
  };

  return (
    <CookiesProvider>
      {i18n && i18n.language ? <View page={page}>{children}</View> : null}

      {isCookieModalOpen ? <CookieComponent onAccept={onAcceptCookie} /> : null}
    </CookiesProvider>
  );
};
