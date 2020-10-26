import React from 'react';
import { useTranslation } from 'react-i18next';

export default () => {
  const { t } = useTranslation('LandingPage', { useSuspense: false });

  return (
    <div className="row justify-content-between">
      <div className="col-12 mb-4 col-md-6 mb-md-0">
        <div className="text-center mb-4">
          <img src="./icon-orange-screen.png" alt={t('SECURITY BY DESIGN')}/>
        </div>

        <h2 className="text-center mb-2">{t('SECURITY BY DESIGN')}</h2>

        <p className="text-center" dangerouslySetInnerHTML={{
              __html: t("Texto2", {
                interpolation: { escapeValue: false },
              }),
            }}>
        </p>
      </div>

      <div className="col-12 col-md-6">
        <div className="text-center mb-4">
          <img src="./icon-orange-sheild.png" alt={t('SECURE DEVELOPMENT')} style={{height: '119px'}}/>
        </div>

        <h2 className="text-center mb-2">{t('SECURE DEVELOPMENT')}</h2>

        <p className="text-center" dangerouslySetInnerHTML={{
              __html: t("Texto3", {
                interpolation: { escapeValue: false },
              }),
            }}>
        </p>
      </div>
    </div>
  );
};
