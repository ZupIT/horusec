import React from 'react';
import {AboutImage} from '../../components/image';
import PreviewComponent from '../../components/image-preview';
import { useTranslation } from 'react-i18next';

export default () => {
  const { t } = useTranslation('LandingPage', { useSuspense: false });

  return (
    <div className="row">
      <div className="col-12 mb-3 col-md-7 mb-md-0">
        <PreviewComponent>
          <AboutImage />
        </PreviewComponent>
      </div>

      <div className="col-12 col-md-5">
        <p className="text-justify" dangerouslySetInnerHTML={{
              __html: t("Texto1", {
                interpolation: { escapeValue: false },
              }),
            }}></p>
      </div>
    </div>
  );
};
