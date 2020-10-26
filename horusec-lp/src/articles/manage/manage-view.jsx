import React from 'react';
import {ManageImage} from '../../components/image';
import Preview from '../../components/image-preview';
import { useTranslation } from 'react-i18next';

export default () => {
  const { t } = useTranslation('LandingPage', { useSuspense: false });

  return (
    <div className="row">
      <div className="col-12 mb-3 col-md-5 mb-md-0">
  <h2 className="mb-4">{t('GERENCIE AS VULNERABILIDADES ENCONTRADAS DE FORMA ANÁLITICA')}</h2>

        <p>
          {t('Além de identificar e centralizar informações o horus disponibiliza uma ferramenta para gerenciamento de acesso e visualização das vulnerabilidades.')}
        </p>
      </div>

      <div className="col-12 col-md-7">
        <Preview>
          <ManageImage />
        </Preview>
      </div>
    </div>
  );
};
